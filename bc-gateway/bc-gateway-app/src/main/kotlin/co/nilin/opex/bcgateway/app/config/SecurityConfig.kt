package co.nilin.opex.bcgateway.app.config

import co.nilin.opex.bcgateway.app.utils.hasRole
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Profile
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.web.reactive.function.client.WebClient

@EnableWebFluxSecurity
class SecurityConfig(@Qualifier("loadBalanced") private val webClient: WebClient,
                     @Qualifier("decWebClient") private val decWebClient: WebClient ) {

    @Value("\${app.auth.cert-url}")
    private lateinit var jwkUrl: String

    @Bean
    @Profile("!otc")
    fun springSecurityFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain? {
        http.csrf().disable()
                .authorizeExchange()
                .pathMatchers("/actuator/**").permitAll()
                .pathMatchers("/swagger-ui/**").permitAll()
                .pathMatchers("/swagger-resources/**").permitAll()
                .pathMatchers("/wallet-sync/**").permitAll()
                .pathMatchers("/currency/**").permitAll()
                .pathMatchers("/filter/**").hasAuthority("SCOPE_trust")
                .pathMatchers("/admin/**").hasRole("SCOPE_trust", "admin_system")
                .pathMatchers("/v1/address/**").permitAll()
                .pathMatchers("/deposit/**").permitAll()
                .pathMatchers("/addresses/**").hasRole("SCOPE_trust", "admin_system")
                .anyExchange().authenticated()
                .and()
                .oauth2ResourceServer()
                .jwt()
        return http.build()
    }


    @Bean
    @Profile("otc")
    fun otcSpringSecurityFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain? {
        http.csrf().disable()
                .authorizeExchange()
                .pathMatchers("/actuator/**").permitAll()
                .pathMatchers("/swagger-ui/**").permitAll()
                .pathMatchers("/swagger-resources/**").permitAll()
                .pathMatchers("/wallet-sync/**").permitAll()
                .pathMatchers("/currency/**").permitAll()
                .pathMatchers("/filter/**").hasAuthority("SCOPE_trust")
                .pathMatchers("/admin/**").hasRole("SCOPE_trust", "admin_system")
                .pathMatchers("/v1/address/**").authenticated()
                .pathMatchers("/deposit/**").permitAll()
                .pathMatchers("/addresses/**").hasRole("SCOPE_trust", "admin_system")
                .anyExchange().authenticated()
                .and()
                .oauth2ResourceServer()
                .jwt()
        return http.build()
    }

    @Bean
    @Profile("!otc")
    @Throws(Exception::class)
    fun reactiveJwtDecoder(): ReactiveJwtDecoder? {
        return NimbusReactiveJwtDecoder.withJwkSetUri(jwkUrl)
                .webClient(webClient)
                .build()
    }

    @Bean
    @Profile("otc")
    @Throws(Exception::class)
    fun otcReactiveJwtDecoder(): ReactiveJwtDecoder? {
        return NimbusReactiveJwtDecoder.withJwkSetUri(jwkUrl)
                .webClient(decWebClient)
                .build()
    }
}
