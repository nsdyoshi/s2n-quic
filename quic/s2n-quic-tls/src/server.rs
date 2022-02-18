// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    certificate::{IntoCertificate, IntoPrivateKey},
    keylog::KeyLogHandle,
    params::Params,
    session::Session,
};
use core::{
    ffi::c_void,
    task::{Context, Poll, Waker},
};
use s2n_codec::EncoderValue;
use s2n_quic_core::{application::ServerName, crypto::tls, endpoint, event::api::ConnectionId};
use s2n_tls::raw::{
    config::{self, Config, ConfigResolver},
    connection::Connection,
    error::Error,
    ffi::*,
    security,
};
use std::sync::Arc;

pub struct Server {
    config: Config,
    #[allow(dead_code)] // we need to hold on to the handle to ensure it is cleaned up correctly
    keylog: Option<KeyLogHandle>,
    config_resolver: Option<Box<dyn ConfigResolver>>,
    params: Params,
}

impl Server {
    pub fn builder() -> Builder {
        Builder::default()
    }
}

impl Default for Server {
    fn default() -> Self {
        Self::builder()
            .build()
            .expect("could not create a default server")
    }
}

pub struct Builder {
    config: config::Builder,
    keylog: Option<KeyLogHandle>,
    config_resolver: Option<Box<dyn ConfigResolver>>,
}

impl Default for Builder {
    fn default() -> Self {
        let mut config = config::Builder::default();
        config.enable_quic().unwrap();
        // https://github.com/aws/s2n-tls/blob/main/docs/USAGE-GUIDE.md#s2n_config_set_cipher_preferences
        config
            .set_security_policy(&security::DEFAULT_TLS13)
            .unwrap();
        config
            .set_application_protocol_preference(&[b"h3"])
            .unwrap();

        Self {
            config,
            keylog: None,
            config_resolver: None,
        }
    }
}

impl Builder {
    pub fn with_config_resolver(
        mut self,
        config_resolver: Box<dyn ConfigResolver>,
    ) -> Result<Self, Error> {
        self.config.set_config_resolver(config_resolver)?;
        Ok(self)
    }

    pub fn with_application_protocols<P: IntoIterator<Item = I>, I: AsRef<[u8]>>(
        mut self,
        protocols: P,
    ) -> Result<Self, Error> {
        self.config.set_application_protocol_preference(protocols)?;
        Ok(self)
    }

    #[deprecated(note = "use `with_application_protocols` instead")]
    pub fn with_alpn_protocols<P: IntoIterator<Item = I>, I: AsRef<[u8]>>(
        self,
        protocols: P,
    ) -> Result<Self, Error> {
        self.with_application_protocols(protocols)
    }

    pub fn with_certificate<C: IntoCertificate, PK: IntoPrivateKey>(
        mut self,
        certificate: C,
        private_key: PK,
    ) -> Result<Self, Error> {
        let certificate = certificate.into_certificate()?;
        let private_key = private_key.into_private_key()?;
        self.config.load_pem(
            certificate
                .0
                .as_pem()
                .expect("pem is currently the only certificate format supported"),
            private_key
                .0
                .as_pem()
                .expect("pem is currently the only certificate format supported"),
        )?;
        Ok(self)
    }

    pub fn with_key_logging(mut self) -> Result<Self, Error> {
        use crate::keylog::KeyLog;

        self.keylog = KeyLog::try_open();

        unsafe {
            // Safety: the KeyLog is stored on `self` to ensure it outlives `config`
            if let Some(keylog) = self.keylog.as_ref() {
                self.config
                    .set_key_log_callback(Some(KeyLog::callback), Arc::as_ptr(keylog) as *mut _)?;
            } else {
                // disable key logging if it failed to create a file
                self.config
                    .set_key_log_callback(None, core::ptr::null_mut())?;
            }
        }

        Ok(self)
    }

    pub fn build(mut self) -> Result<Server, Error> {
        // if let Some(config_resolver) = self.config_resolver {
        unsafe {
            self.config
                .set_client_hello_callback_mode(s2n_client_hello_cb_mode::NONBLOCKING)?;

            let context = 4 as *mut c_void;
            self.config
                .set_client_hello_callback(Some(client_hello_cb), context)
                .unwrap();
        }
        // }

        Ok(Server {
            config: self.config.build()?,
            keylog: self.keylog,
            config_resolver: self.config_resolver,
            params: Default::default(),
        })
    }
}

struct ClientHelloCb {
    config_resolver: Box<dyn ConfigResolver>,
    waker: Waker,
}

/// The function s2n-tls calls when it emits secrets
unsafe extern "C" fn client_hello_cb(
    conn: *mut s2n_connection,
    context: *mut ::libc::c_void,
) -> s2n_status_code::Type {
    let context = &mut *(context as *mut ClientHelloCb);
    let mut future_context = Context::from_waker(&context.waker);

    // let client_hello = Connection::get_client_hello(conn) as &mut s2n_client_hello;
    let client_hello = todo!();

    match context
        .config_resolver
        .poll_config(&mut future_context, client_hello)
    {
        Poll::Ready(Ok(config)) => {
            Connection::client_hello_callback_done(conn).unwrap();
            // set new config on connection
            Connection::set_config_raw(conn, config).unwrap();

            s2n_status_code::SUCCESS
        }
        Poll::Ready(Err(_err)) => s2n_status_code::FAILURE,
        Poll::Pending => s2n_status_code::SUCCESS,
    }
}

impl tls::Endpoint for Server {
    type Session = Session;

    fn new_server_session<Params: EncoderValue>(&mut self, params: &Params) -> Self::Session {
        let config = self.config.clone();
        let config_resolver = self.config_resolver.take();
        self.params.with(params, |params| {
            Session::new(endpoint::Type::Server, config, params, config_resolver).unwrap()
        })
    }

    fn new_client_session<Params: EncoderValue>(
        &mut self,
        _transport_parameters: &Params,
        _erver_name: ServerName,
    ) -> Self::Session {
        panic!("cannot create a client session from a server config");
    }

    fn max_tag_length(&self) -> usize {
        s2n_quic_ring::MAX_TAG_LEN
    }
}
