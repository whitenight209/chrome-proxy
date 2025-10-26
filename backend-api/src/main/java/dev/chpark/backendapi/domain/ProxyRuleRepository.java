package dev.chpark.backendapi.domain;

import java.util.List;
import java.util.Optional;

public interface ProxyRuleRepository {
    ProxyRule save(ProxyRule rule);
    Optional<ProxyRule> findById(Long id);
    List<ProxyRule> findAll();
    void deleteById(Long id);
}