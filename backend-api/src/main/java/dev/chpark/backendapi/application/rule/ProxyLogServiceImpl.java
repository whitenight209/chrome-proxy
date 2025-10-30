package dev.chpark.backendapi.application.rule;

import com.google.protobuf.Empty;
import io.grpc.stub.StreamObserver;
import lombok.extern.slf4j.Slf4j;
import net.devh.boot.grpc.server.service.GrpcService;
import proxy.HttpProxy;
import proxy.ProxyNotifierGrpc;

@Slf4j
@GrpcService
public class ProxyLogServiceImpl extends ProxyNotifierGrpc.ProxyNotifierImplBase {
    @Override
    public void sendProxyEvent(HttpProxy.ProxyEvent request, StreamObserver<Empty> responseObserver) {
        String requestId = request.getRequestId();
        log.info("requestId:{}", requestId);
        responseObserver.onNext(Empty.getDefaultInstance());
        responseObserver.onCompleted();
    }
}
