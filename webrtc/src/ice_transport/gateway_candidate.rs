use super::{RTCIceCandidate, RTCIceTransport};

impl RTCIceTransport {
    pub async fn gather_gateway_candidate(&self) -> Option<RTCIceCandidate> {
        let agent = self.gatherer.get_agent().await?;
        Some(RTCIceCandidate::from(
            &agent.gather_gateway_candidate().await?,
        ))
    }
}
