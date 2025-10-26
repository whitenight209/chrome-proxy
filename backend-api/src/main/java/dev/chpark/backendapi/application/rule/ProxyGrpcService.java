package dev.chpark.backendapi.application.rule;

import dev.chpark.backendapi.gprc.StreamAck;
import dev.chpark.backendapi.gprc.Trace;
import dev.chpark.backendapi.gprc.TraceServiceGrpc;
import io.grpc.stub.StreamObserver;
import net.devh.boot.grpc.server.service.GrpcService;

@GrpcService
public class ProxyGrpcService extends TraceServiceGrpc.TraceServiceImplBase {

    @Override
    public StreamObserver<Trace> streamTraces(StreamObserver<StreamAck> responseObserver) {
        return super.streamTraces(responseObserver);
    }
}
