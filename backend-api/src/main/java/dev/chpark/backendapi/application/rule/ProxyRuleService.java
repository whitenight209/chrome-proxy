package dev.chpark.backendapi.application.rule;

import dev.chpark.backendapi.domain.ProxyRule;
import dev.chpark.backendapi.domain.ProxyRuleRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ProxyRuleService {

    private final ProxyRuleRepository repo;

    public ProxyRuleService(ProxyRuleRepository repo) {
        this.repo = repo;
    }

    public ProxyRule create(ProxyRule rule) {
        return repo.save(rule);
    }

    public List<ProxyRule> list() {
        return repo.findAll();
    }

    public ProxyRule get(Long id) {
        return repo.findById(id).orElseThrow();
    }

    public ProxyRule update(Long id, ProxyRule newRule) {
        return repo.findById(id).map(rule -> {
            rule.updateFrom(newRule);
            return repo.save(rule);
        }).orElseThrow();
    }

    public void delete(Long id) {
        repo.deleteById(id);
    }
}