use std::{collections::HashMap, net::SocketAddr};

use crate::{rendezvous_proto::{punch_hole_response, PunchHoleRequest, PunchHoleResponse, RendezvousMessage}, ResultType};

#[inline]
pub async fn handle_punch_hole_request(
    id_map: &mut HashMap<String, SocketAddr>, 
    ph: PunchHoleRequest,
    key: &str
) -> ResultType<(RendezvousMessage, Option<SocketAddr>)> {
    log::info!("id_map:{:#?} ph:{:#?} key:{:#?}", id_map, ph, key);
    let mut ph = ph;
    if !key.is_empty() && ph.licence_key != key {
        let mut msg_out = RendezvousMessage::new();
        msg_out.set_punch_hole_response(PunchHoleResponse {
            failure: punch_hole_response::Failure::LICENSE_MISMATCH.into(),
            ..Default::default()
        });
        return Ok((msg_out, None));
    }
    let id = ph.id;

    if let Some(peer) = id_map.get(&id) {
        let mut msg_out = RendezvousMessage::new();
            msg_out.set_punch_hole_response(PunchHoleResponse {
                failure: punch_hole_response::Failure::ID_NOT_EXIST.into(),
                ..Default::default()
            });
            Ok((msg_out, None))
    } else {
        let mut msg_out = RendezvousMessage::new();
        msg_out.set_punch_hole_response(PunchHoleResponse {
            failure: punch_hole_response::Failure::ID_NOT_EXIST.into(),
            ..Default::default()
        });
        Ok((msg_out, None))
    }
}