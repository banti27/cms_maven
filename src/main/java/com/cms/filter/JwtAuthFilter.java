package com.cms.filter;

import java.io.IOException;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.cms.service.JwtService;
import com.cms.service.UserService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

	private final JwtService jwtService;
	private final UserService userService;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		// Get Authorization header from the Http Request
		final String authHeader = request.getHeader("Authorization");

		// check if authHeadr is empty or it does not starts with "Bearer "
		if (StringUtils.isBlank(authHeader) || !StringUtils.startsWith(authHeader, "Bearer ")) {
			filterChain.doFilter(request, response);
			return;
		}

		// extract JWT and userEmail
		String jwt = authHeader.substring(7);
		String userEmail = this.jwtService.extractUsername(jwt);

		if (StringUtils.isNotEmpty(userEmail) && SecurityContextHolder.getContext().getAuthentication() == null) {

			// load the UserDetails from the userEmail
			UserDetails userDetails = this.userService.userDetailsService().loadUserByUsername(userEmail);

			if (this.jwtService.isTokenValid(jwt, userDetails)) {

				// creating a WebAuthenticationDetailsSource object
				WebAuthenticationDetailsSource details = new WebAuthenticationDetailsSource();
				details.buildDetails(request);

				// creating a UsernamePasswordAuthenticationToken object
				UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(userDetails, null,
						userDetails.getAuthorities());
				token.setDetails(details);

				// creating an empty SecurityContext object
				SecurityContext context = SecurityContextHolder.createEmptyContext();
				context.setAuthentication(token);

				// set the security context
				SecurityContextHolder.setContext(context);
			}

		}

		// we need to pass the request to other filter
		filterChain.doFilter(request, response);
	}

}
