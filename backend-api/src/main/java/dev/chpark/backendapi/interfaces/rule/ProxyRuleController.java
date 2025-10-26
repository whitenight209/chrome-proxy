package dev.chpark.backendapi.interfaces.rule;

import dev.chpark.backendapi.application.rule.ProxyRuleService;
import dev.chpark.backendapi.domain.ProxyRule;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/rules")
public class ProxyRuleController {

    private final ProxyRuleService service;

    public ProxyRuleController(ProxyRuleService service) {
        this.service = service;
    }

    @PostMapping
    public ProxyRule create(@RequestBody ProxyRule rule) {
        return service.create(rule);
    }

    @GetMapping
    public List<ProxyRule> list() {
        return service.list();
    }

    @GetMapping("/{id}")
    public ProxyRule get(@PathVariable Long id) {
        return service.get(id);
    }

    @PutMapping("/{id}")
    public ProxyRule update(@PathVariable Long id, @RequestBody ProxyRule rule) {
        return service.update(id, rule);
    }

    @DeleteMapping("/{id}")
    public void delete(@PathVariable Long id) {
        service.delete(id);
    }
}