package dev.chpark.backendapi.infrastructure.persistence;

import dev.chpark.backendapi.domain.ProxyRule;
import dev.chpark.backendapi.domain.ProxyRuleRepository;
import org.springframework.data.jpa.repository.JpaRepository;

public interface JpaProxyRuleRepository extends JpaRepository<ProxyRule, Long>, ProxyRuleRepository {
}
