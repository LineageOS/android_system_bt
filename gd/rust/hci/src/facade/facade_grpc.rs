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

const METHOD_HCI_LAYER_FACADE_ENQUEUE_COMMAND_WITH_COMPLETE: ::grpcio::Method<super::facade::CommandMsg, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/bluetooth.hci.HciLayerFacade/EnqueueCommandWithComplete",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_HCI_LAYER_FACADE_ENQUEUE_COMMAND_WITH_STATUS: ::grpcio::Method<super::facade::CommandMsg, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/bluetooth.hci.HciLayerFacade/EnqueueCommandWithStatus",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_HCI_LAYER_FACADE_REGISTER_EVENT_HANDLER: ::grpcio::Method<super::facade::EventCodeMsg, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/bluetooth.hci.HciLayerFacade/RegisterEventHandler",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_HCI_LAYER_FACADE_REGISTER_LE_EVENT_HANDLER: ::grpcio::Method<super::facade::LeSubeventCodeMsg, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/bluetooth.hci.HciLayerFacade/RegisterLeEventHandler",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_HCI_LAYER_FACADE_SEND_ACL_DATA: ::grpcio::Method<super::facade::AclMsg, super::empty::Empty> = ::grpcio::Method {
    ty: ::grpcio::MethodType::Unary,
    name: "/bluetooth.hci.HciLayerFacade/SendAclData",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_HCI_LAYER_FACADE_FETCH_EVENTS: ::grpcio::Method<super::empty::Empty, super::facade::EventMsg> = ::grpcio::Method {
    ty: ::grpcio::MethodType::ServerStreaming,
    name: "/bluetooth.hci.HciLayerFacade/FetchEvents",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_HCI_LAYER_FACADE_FETCH_LE_SUBEVENTS: ::grpcio::Method<super::empty::Empty, super::facade::LeSubeventMsg> = ::grpcio::Method {
    ty: ::grpcio::MethodType::ServerStreaming,
    name: "/bluetooth.hci.HciLayerFacade/FetchLeSubevents",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

const METHOD_HCI_LAYER_FACADE_FETCH_ACL_PACKETS: ::grpcio::Method<super::empty::Empty, super::facade::AclMsg> = ::grpcio::Method {
    ty: ::grpcio::MethodType::ServerStreaming,
    name: "/bluetooth.hci.HciLayerFacade/FetchAclPackets",
    req_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
    resp_mar: ::grpcio::Marshaller { ser: ::grpcio::pb_ser, de: ::grpcio::pb_de },
};

#[derive(Clone)]
pub struct HciLayerFacadeClient {
    client: ::grpcio::Client,
}

impl HciLayerFacadeClient {
    pub fn new(channel: ::grpcio::Channel) -> Self {
        HciLayerFacadeClient {
            client: ::grpcio::Client::new(channel),
        }
    }

    pub fn enqueue_command_with_complete_opt(&self, req: &super::facade::CommandMsg, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_HCI_LAYER_FACADE_ENQUEUE_COMMAND_WITH_COMPLETE, req, opt)
    }

    pub fn enqueue_command_with_complete(&self, req: &super::facade::CommandMsg) -> ::grpcio::Result<super::empty::Empty> {
        self.enqueue_command_with_complete_opt(req, ::grpcio::CallOption::default())
    }

    pub fn enqueue_command_with_complete_async_opt(&self, req: &super::facade::CommandMsg, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_HCI_LAYER_FACADE_ENQUEUE_COMMAND_WITH_COMPLETE, req, opt)
    }

    pub fn enqueue_command_with_complete_async(&self, req: &super::facade::CommandMsg) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.enqueue_command_with_complete_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn enqueue_command_with_status_opt(&self, req: &super::facade::CommandMsg, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_HCI_LAYER_FACADE_ENQUEUE_COMMAND_WITH_STATUS, req, opt)
    }

    pub fn enqueue_command_with_status(&self, req: &super::facade::CommandMsg) -> ::grpcio::Result<super::empty::Empty> {
        self.enqueue_command_with_status_opt(req, ::grpcio::CallOption::default())
    }

    pub fn enqueue_command_with_status_async_opt(&self, req: &super::facade::CommandMsg, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_HCI_LAYER_FACADE_ENQUEUE_COMMAND_WITH_STATUS, req, opt)
    }

    pub fn enqueue_command_with_status_async(&self, req: &super::facade::CommandMsg) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.enqueue_command_with_status_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn register_event_handler_opt(&self, req: &super::facade::EventCodeMsg, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_HCI_LAYER_FACADE_REGISTER_EVENT_HANDLER, req, opt)
    }

    pub fn register_event_handler(&self, req: &super::facade::EventCodeMsg) -> ::grpcio::Result<super::empty::Empty> {
        self.register_event_handler_opt(req, ::grpcio::CallOption::default())
    }

    pub fn register_event_handler_async_opt(&self, req: &super::facade::EventCodeMsg, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_HCI_LAYER_FACADE_REGISTER_EVENT_HANDLER, req, opt)
    }

    pub fn register_event_handler_async(&self, req: &super::facade::EventCodeMsg) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.register_event_handler_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn register_le_event_handler_opt(&self, req: &super::facade::LeSubeventCodeMsg, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_HCI_LAYER_FACADE_REGISTER_LE_EVENT_HANDLER, req, opt)
    }

    pub fn register_le_event_handler(&self, req: &super::facade::LeSubeventCodeMsg) -> ::grpcio::Result<super::empty::Empty> {
        self.register_le_event_handler_opt(req, ::grpcio::CallOption::default())
    }

    pub fn register_le_event_handler_async_opt(&self, req: &super::facade::LeSubeventCodeMsg, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_HCI_LAYER_FACADE_REGISTER_LE_EVENT_HANDLER, req, opt)
    }

    pub fn register_le_event_handler_async(&self, req: &super::facade::LeSubeventCodeMsg) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.register_le_event_handler_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn send_acl_data_opt(&self, req: &super::facade::AclMsg, opt: ::grpcio::CallOption) -> ::grpcio::Result<super::empty::Empty> {
        self.client.unary_call(&METHOD_HCI_LAYER_FACADE_SEND_ACL_DATA, req, opt)
    }

    pub fn send_acl_data(&self, req: &super::facade::AclMsg) -> ::grpcio::Result<super::empty::Empty> {
        self.send_acl_data_opt(req, ::grpcio::CallOption::default())
    }

    pub fn send_acl_data_async_opt(&self, req: &super::facade::AclMsg, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.client.unary_call_async(&METHOD_HCI_LAYER_FACADE_SEND_ACL_DATA, req, opt)
    }

    pub fn send_acl_data_async(&self, req: &super::facade::AclMsg) -> ::grpcio::Result<::grpcio::ClientUnaryReceiver<super::empty::Empty>> {
        self.send_acl_data_async_opt(req, ::grpcio::CallOption::default())
    }

    pub fn fetch_events_opt(&self, req: &super::empty::Empty, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientSStreamReceiver<super::facade::EventMsg>> {
        self.client.server_streaming(&METHOD_HCI_LAYER_FACADE_FETCH_EVENTS, req, opt)
    }

    pub fn fetch_events(&self, req: &super::empty::Empty) -> ::grpcio::Result<::grpcio::ClientSStreamReceiver<super::facade::EventMsg>> {
        self.fetch_events_opt(req, ::grpcio::CallOption::default())
    }

    pub fn fetch_le_subevents_opt(&self, req: &super::empty::Empty, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientSStreamReceiver<super::facade::LeSubeventMsg>> {
        self.client.server_streaming(&METHOD_HCI_LAYER_FACADE_FETCH_LE_SUBEVENTS, req, opt)
    }

    pub fn fetch_le_subevents(&self, req: &super::empty::Empty) -> ::grpcio::Result<::grpcio::ClientSStreamReceiver<super::facade::LeSubeventMsg>> {
        self.fetch_le_subevents_opt(req, ::grpcio::CallOption::default())
    }

    pub fn fetch_acl_packets_opt(&self, req: &super::empty::Empty, opt: ::grpcio::CallOption) -> ::grpcio::Result<::grpcio::ClientSStreamReceiver<super::facade::AclMsg>> {
        self.client.server_streaming(&METHOD_HCI_LAYER_FACADE_FETCH_ACL_PACKETS, req, opt)
    }

    pub fn fetch_acl_packets(&self, req: &super::empty::Empty) -> ::grpcio::Result<::grpcio::ClientSStreamReceiver<super::facade::AclMsg>> {
        self.fetch_acl_packets_opt(req, ::grpcio::CallOption::default())
    }
    pub fn spawn<F>(&self, f: F) where F: ::futures::Future<Output = ()> + Send + 'static {
        self.client.spawn(f)
    }
}

pub trait HciLayerFacade {
    fn enqueue_command_with_complete(&mut self, ctx: ::grpcio::RpcContext, req: super::facade::CommandMsg, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn enqueue_command_with_status(&mut self, ctx: ::grpcio::RpcContext, req: super::facade::CommandMsg, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn register_event_handler(&mut self, ctx: ::grpcio::RpcContext, req: super::facade::EventCodeMsg, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn register_le_event_handler(&mut self, ctx: ::grpcio::RpcContext, req: super::facade::LeSubeventCodeMsg, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn send_acl_data(&mut self, ctx: ::grpcio::RpcContext, req: super::facade::AclMsg, sink: ::grpcio::UnarySink<super::empty::Empty>);
    fn fetch_events(&mut self, ctx: ::grpcio::RpcContext, req: super::empty::Empty, sink: ::grpcio::ServerStreamingSink<super::facade::EventMsg>);
    fn fetch_le_subevents(&mut self, ctx: ::grpcio::RpcContext, req: super::empty::Empty, sink: ::grpcio::ServerStreamingSink<super::facade::LeSubeventMsg>);
    fn fetch_acl_packets(&mut self, ctx: ::grpcio::RpcContext, req: super::empty::Empty, sink: ::grpcio::ServerStreamingSink<super::facade::AclMsg>);
}

pub fn create_hci_layer_facade<S: HciLayerFacade + Send + Clone + 'static>(s: S) -> ::grpcio::Service {
    let mut builder = ::grpcio::ServiceBuilder::new();
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_HCI_LAYER_FACADE_ENQUEUE_COMMAND_WITH_COMPLETE, move |ctx, req, resp| {
        instance.enqueue_command_with_complete(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_HCI_LAYER_FACADE_ENQUEUE_COMMAND_WITH_STATUS, move |ctx, req, resp| {
        instance.enqueue_command_with_status(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_HCI_LAYER_FACADE_REGISTER_EVENT_HANDLER, move |ctx, req, resp| {
        instance.register_event_handler(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_HCI_LAYER_FACADE_REGISTER_LE_EVENT_HANDLER, move |ctx, req, resp| {
        instance.register_le_event_handler(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_unary_handler(&METHOD_HCI_LAYER_FACADE_SEND_ACL_DATA, move |ctx, req, resp| {
        instance.send_acl_data(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_server_streaming_handler(&METHOD_HCI_LAYER_FACADE_FETCH_EVENTS, move |ctx, req, resp| {
        instance.fetch_events(ctx, req, resp)
    });
    let mut instance = s.clone();
    builder = builder.add_server_streaming_handler(&METHOD_HCI_LAYER_FACADE_FETCH_LE_SUBEVENTS, move |ctx, req, resp| {
        instance.fetch_le_subevents(ctx, req, resp)
    });
    let mut instance = s;
    builder = builder.add_server_streaming_handler(&METHOD_HCI_LAYER_FACADE_FETCH_ACL_PACKETS, move |ctx, req, resp| {
        instance.fetch_acl_packets(ctx, req, resp)
    });
    builder.build()
}
