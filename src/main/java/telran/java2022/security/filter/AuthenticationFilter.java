package telran.java2022.security.filter;

import java.io.IOException;
import java.security.Principal;
import java.util.Base64;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import telran.java2022.accounting.dao.UserAccountRepository;
import telran.java2022.accounting.model.UserAccount;
import telran.java2022.post.dao.PostRepository;
import telran.java2022.security.context.SecurityContext;
import telran.java2022.security.context.User;
import telran.java2022.security.service.SessionService;

@Component
@RequiredArgsConstructor
@Order(10)
public class AuthenticationFilter implements Filter {

	final UserAccountRepository userAccountRepository;
	final PostRepository postRepository;
	final SecurityContext context;
	final SessionService sessionService;

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		if (checkEndPoint(request.getMethod(), request.getServletPath())) {
			String sessionId = request.getSession().getId();
			UserAccount userAccount = sessionService.getUser(sessionId);
			String token = request.getHeader("Authorization");
			if (token != null) {
				request.changeSessionId();
				sessionId = request.getSession().getId();
				userAccount = sessionService.getUser(sessionId);
				if (userAccount != null) {
					response.sendError(401);
					return;
				}
				String[] credentials;
				try {
					credentials = getCredentialsFromToken(token);
				} catch (Exception e) {
					response.sendError(401, "Invalid token");
					return;
				}
				userAccount = userAccountRepository.findById(credentials[0]).orElse(null);
				if (userAccount == null || !BCrypt.checkpw(credentials[1], userAccount.getPassword())) {
					response.sendError(401, "login or password is invalid");
					return;
				}
				sessionService.addUser(sessionId, userAccount);
			}
			try {
				request = new WrappedRequest(request, userAccount.getLogin());
				User user = User.builder().userName(userAccount.getLogin()).password(userAccount.getPassword())
						.roles(userAccount.getRoles()).build();
				context.addUser(user);
			} catch (Exception e) {
				response.sendError(401, "Authorization failed");
				return;
			}
		}
		chain.doFilter(request, response);
	}

	private String[] getCredentialsFromToken(String token) {
		String[] basicAuth = token.split(" ");
		String decode = new String(Base64.getDecoder().decode(basicAuth[1]));
		String[] credentials = decode.split(":");
		return credentials;
	}

	private boolean checkEndPoint(String method, String servletPath) {
		return !("POST".equalsIgnoreCase(method) && servletPath.matches("/account/register/?"))
				&& !("GET".equalsIgnoreCase(method) && servletPath.matches("/forum/posts/author/\\w/?"))
				&& !("POST".equalsIgnoreCase(method) && servletPath.matches("/forum/posts/tags/?"))
				&& !("POST".equalsIgnoreCase(method) && servletPath.matches("forum/posts/period/?"));
	}

	private class WrappedRequest extends HttpServletRequestWrapper {
		String login;

		public WrappedRequest(HttpServletRequest request, String login) {
			super(request);
			this.login = login;
		}

		@Override
		public Principal getUserPrincipal() {
			return () -> login;
		}

	}

}
