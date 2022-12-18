package ads02.gateway.filter;

import ads02.gateway.service.JwtService;
import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Objects;

@Component
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AbstractGatewayFilterFactory.NameConfig> {

    private final JwtService jwtService;

    @Autowired
    public AuthorizationHeaderFilter(JwtService jwtService) {
        super(AbstractGatewayFilterFactory.NameConfig.class);
        this.jwtService = jwtService;
    }

    @Override
    public GatewayFilter apply(NameConfig config) {
        return ((exchange, chain) -> {
            ServerHttpRequest req = (ServerHttpRequest) exchange.getRequest();
            if (!req.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)){
                return onError(exchange, "토큰을 포함해주세요", HttpStatus.UNAUTHORIZED);
            }
            String authorization = Objects.requireNonNull(req.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0));
            String token = authorization.replace("Bearer", "").trim();
            if (!jwtService.isValid(token)){
                return onError(exchange, "토큰이 유효하지 않습니다.", HttpStatus.UNAUTHORIZED);
            }
            populateRequestWithHeaders(exchange, token);
            return chain.filter(exchange);
        });
    }

    private void populateRequestWithHeaders(ServerWebExchange exchange, String token) {
        String id = jwtService.getClaimFromJwt("id", token);
        String bojToken = jwtService.getClaimFromJwt("bojToken", token);
        exchange.getRequest().mutate()
                .header("id", id)
                .header("bojToken", bojToken)
                .build();
    }

    private Mono<Void> onError(ServerWebExchange exchange, String o, HttpStatus status){
        ServerHttpResponse res = exchange.getResponse();
        res.setStatusCode(status);
        return res.setComplete();
    }
}
