// This file is generated. Do not edit
// @generated

// https://github.com/Manishearth/rust-clippy/issues/702
#![allow(unknown_lints)]
#![allow(clippy::all)]

#![cfg_attr(rustfmt, rustfmt_skip)]

#![allow(box_pointers)]
#![allow(dead_code)]
#![allow(missing_docs)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(trivial_casts)]
#![allow(unsafe_code)]
#![allow(unused_imports)]
#![allow(unused_results)]

const METHOD_ROOT_FACADE_START_STACK: ::grpcio::Method<super::rootservice::StartStackRequest, super::rootservice::StartStackResponse> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/bluetooth.facade.RootFacade/StartStack",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_ROOT_FACADE_STOP_STACK: ::grpcio::Method<super::rootservice::StopStackRequest, super::rootservice::StopStackResponse> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/bluetooth.facade.RootFacade/StopStack",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

#[derive(Clone)]
pub struct RootFacadeClient {
    client: ::grpcio::Client,
}

impl RootFacadeClient {
    pub fn new(channel: ::grpcio::Channel) -> Self {
        RootFacadeClient {
            client: ::grpcio::Client::new(channel),
        }
    }

    pub fn start_stack_opt(&self, req: &super::rootservice::StartStackRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::rootservice::StartStackResponse> {
        self.client.unary_call(&METHOD_ROOT_FACADE_START_STACK, req, opt)
    }

    pub fn start_stack(&self, req: &super::rootservice::StartStackRequest) -> ::grpcio::Result<super::rootservice::StartStackResponse> {
        self.start_stack_opt(req, ::grpcio::CallOption::default())
    }

    pub fn start_stack_async_opt(&self, req: &super::rootservice::StartStackRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::rootservice::StartStackResponse>> {
        self.client.unary_call_async(&METHOD_ROOT_FACADE_START_STACK, req, opt)
    }

    pub fn start_stack_async(&self, req: &super::rootservice::StartStackRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::rootservice::StartStackResponse>> {
        self.start_stack_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn stop_stack_opt(&self, req: &super::rootservice::StopStackRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::rootservice::StopStackResponse> {
        self.client.unary_call(&METHOD_ROOT_FACADE_STOP_STACK, req, opt)
    }

    pub fn stop_stack(&self, req: &super::rootservice::StopStackRequest) -> ::grpcio::Result<super::rootservice::StopStackResponse> {
        self.stop_stack_opt(req, ::grpcio::CallOption::default())
    }

    pub fn stop_stack_async_opt(&self, req: &super::rootservice::StopStackRequest, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::rootservice::StopStackResponse>> {
        self.client.unary_call_async(&METHOD_ROOT_FACADE_STOP_STACK, req, opt)
    }

    pub fn stop_stack_async(&self, req: &super::rootservice::StopStackRequest) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::rootservice::StopStackResponse>> {
        self.stop_stack_async_opt(req, ::grpcio::CallOption::default())
    }
    pub fn spawn<F>(&self, f: F) where F: ::futures::Future<Output = ()> + Send + 'static {
        self.client.spawn(f)
    }
}

pub trait RootFacade {
    fn start_stack(&mut self, ctx: ::grpcio::RpcContext, req: super::rootservice::StartStackRequest, sink: ::grpcio::UnarySink<super::rootservice::StartStackResponse>);
    fn stop_stack(&mut self, ctx: ::grpcio::RpcContext, req: super::rootservice::StopStackRequest, sink: ::grpcio::UnarySink<super::rootservice::StopStackResponse>);
}

pub fn create_root_facade<S: RootFacade + Send + Clone + 'static>(s: S) -> ::grpcio::Service {
    let mut builder = ::grpcio::ServiceBuilder::new();
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_ROOT_FACADE_START_STACK, move |ctx, req, resp| {
        instance.start_stack(ctx, req, resp)
    });
    let mut instance = s;
    builder = builder.add_unary_handler(&METHOD_ROOT_FACADE_STOP_STACK, move |ctx, req, resp| {
        instance.stop_stack(ctx, req, resp)
    });
    builder.build()
}

const METHOD_READ_ONLY_PROPERTY_READ_LOCAL_ADDRESS: ::grpcio::Method<super::empty::Empty, super::common::BluetoothAddress> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/bluetooth.facade.ReadOnlyProperty/ReadLocalAddress",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

#[derive(Clone)]
pub struct ReadOnlyPropertyClient {
    client: ::grpcio::Client,
}

impl ReadOnlyPropertyClient {
    pub fn new(channel: ::grpcio::Channel) -> Self {
        ReadOnlyPropertyClient {
            client: ::grpcio::Client::new(channel),
        }
    }

    pub fn read_local_address_opt(&self, req: &super::empty::Empty, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::common::BluetoothAddress> {
        self.client.unary_call(&METHOD_READ_ONLY_PROPERTY_READ_LOCAL_ADDRESS, req, opt)
    }

    pub fn read_local_address(&self, req: &super::empty::Empty) -> ::grpcio::Result<super::common::BluetoothAddress> {
        self.read_local_address_opt(req, ::grpcio::CallOption::default())
    }

    pub fn read_local_address_async_opt(&self, req: &super::empty::Empty, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::common::BluetoothAddress>> {
        self.client.unary_call_async(&METHOD_READ_ONLY_PROPERTY_READ_LOCAL_ADDRESS, req, opt)
    }

    pub fn read_local_address_async(&self, req: &super::empty::Empty) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::common::BluetoothAddress>> {
        self.read_local_address_async_opt(req, ::grpcio::CallOption::default())
    }
    pub fn spawn<F>(&self, f: F) where F: ::futures::Future<Output = ()> + Send + 'static {
        self.client.spawn(f)
    }
}

pub trait ReadOnlyProperty {
    fn read_local_address(&mut self, ctx: ::grpcio::RpcContext, req: super::empty::Empty, sink: ::grpcio::UnarySink<super::common::BluetoothAddress>);
}

pub fn create_read_only_property<S: ReadOnlyProperty + Send + Clone + 'static>(s: S) -> ::grpcio::Service {
    let mut builder = ::grpcio::ServiceBuilder::new();
    let mut instance = s;
    builder = builder.add_unary_handler(&METHOD_READ_ONLY_PROPERTY_READ_LOCAL_ADDRESS, move |ctx, req, resp| {
        instance.read_local_address(ctx, req, resp)
    });
    builder.build()
}
