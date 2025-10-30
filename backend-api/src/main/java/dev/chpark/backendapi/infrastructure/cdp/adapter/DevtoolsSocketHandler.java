package dev.chpark.backendapi.infrastructure.cdp.adapter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.*;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Component
public class DevtoolsSocketHandler extends TextWebSocketHandler {

    private final ObjectMapper mapper = new ObjectMapper();
    private final ConcurrentHashMap<String, WebSocketSession> sessions = new ConcurrentHashMap<>();

    @Override
    public void afterConnectionEstablished(WebSocketSession session) {
        sessions.put(session.getId(), session);
        log.info("Client connected: {}", session.getId());
    }

    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) throws IOException {
        String payload = message.getPayload();
        JsonNode node = mapper.readTree(payload);
        log.info("Received: {}", node);

        // JSON에서 "id" 필드 추출 (없으면 null 반환)
        JsonNode idNode = node.get("id");

        // id가 존재할 경우 값, 없으면 null 사용
        String idValue = (idNode != null && !idNode.isNull()) ? idNode.asText() : null;

        // 응답 JSON 구성
        ObjectNode response = mapper.createObjectNode();
        if (idValue != null) {
            // id가 숫자인 경우 정수로 넣고, 문자열이면 문자열로 넣기
            if (idNode.isInt() || idNode.isLong()) {
                response.put("id", idNode.asLong());
            } else {
                response.put("id", idValue);
            }
        }
        response.set("result", mapper.createObjectNode()); // 빈 JSON 객체 {}

        // WebSocket으로 응답 전송
        session.sendMessage(new TextMessage(mapper.writeValueAsString(response)));
    }

    private void sendResponse(WebSocketSession session, int id, String resultJson) throws IOException {
        String response = String.format("{\"id\": %d, \"result\": %s}", id, resultJson);
        session.sendMessage(new TextMessage(response));
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) {
        String reason = status.getReason();
        log.info("Client disconnected {} reason: {}", session.getId(), reason);
        sessions.remove(session.getId());
    }
}
