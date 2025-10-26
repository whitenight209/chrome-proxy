package dev.chpark.backendapi.domain;

import jakarta.persistence.*;
import lombok.NoArgsConstructor;

import java.time.OffsetDateTime;

@Entity
@Table(name = "proxy_rules",
        uniqueConstraints = @UniqueConstraint(columnNames = {"hostPattern","pathPattern","httpMethod"}))
@NoArgsConstructor
public class ProxyRule {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String hostPattern;
    private String pathPattern;
    private String httpMethod;

    @Enumerated(EnumType.STRING)
    private Action action;

    @Lob
    private String replaceBody;

    private Integer replaceStatus;
    private boolean enabled = true;
    private String description;

    private OffsetDateTime createdAt = OffsetDateTime.now();
    private OffsetDateTime updatedAt = OffsetDateTime.now();

    @PreUpdate
    public void onUpdate() {
        updatedAt = OffsetDateTime.now();
    }
    public void updateFrom(ProxyRule source) {
        this.hostPattern = source.hostPattern;
        this.pathPattern = source.pathPattern;
        this.httpMethod = source.httpMethod;
        this.action = source.action;
        this.replaceBody = source.replaceBody;
        this.replaceStatus = source.replaceStatus;
        this.enabled = source.enabled;
        this.description = source.description;
    }
}