package telran.java2022.security.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import telran.java2022.post.dao.PostRepository;
import telran.java2022.post.model.Post;
import telran.java2022.security.context.SecurityContext;
import telran.java2022.security.context.User;

@Component
@RequiredArgsConstructor
@Order(30)
public class UserFilter implements Filter {

	final PostRepository postRepository;
	final SecurityContext context;

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;

		if (checkEndPoint(request.getMethod(), request.getServletPath())) {
			User userAccount = context.getUser(request.getUserPrincipal().getName());
			if (("PUT".equalsIgnoreCase(request.getMethod()) || "DELETE".equalsIgnoreCase(request.getMethod()))
					&& request.getServletPath().matches("/forum/post/\\w+/?")) {
				String namePost = request.getServletPath().split("/")[3];
				Post post = postRepository.findById(namePost).get();
				if (!userAccount.getUserName().equals(postRepository.findById(post.getId()).get().getAuthor())
						&& !checkPostDeleteMethod(request.getMethod(), request.getServletPath(), userAccount)) {
					response.sendError(403, "Error post");
					return;
				}
			}
			if (("PUT".equalsIgnoreCase(request.getMethod())
					&& request.getServletPath().matches("/forum/post/\\w+/comment/\\w+/?"))) {
				String name = request.getServletPath().split("/")[5];
				if (!(userAccount.getUserName().equals(name))) {
					response.sendError(403, "Error User");
					return;
				}
			}
			if (!request.getServletPath().matches("/account/password/?")
					&& ("POST".equalsIgnoreCase(request.getMethod())
							&& request.getServletPath().matches("/forum/post/\\w+"))) {
				String name = request.getServletPath().split("/")[3];
				if (!(userAccount.getUserName().equals(name))
						&& !checkUserDeleteMethod(request.getMethod(), request.getServletPath(), userAccount)) {
					response.sendError(403, "Error User");
					return;
				}
			}
		}
		chain.doFilter(request, response);
	}

	private boolean checkPostDeleteMethod(String method, String servletPath, User userAccount) {
		return ("DELETE".equalsIgnoreCase(method) && servletPath.matches("/forum/post/\\w+/?"))
				&& userAccount.getRoles().contains("Moderator".toUpperCase());
	}

	private boolean checkUserDeleteMethod(String method, String servletPath, User userAccount) {
		return ("DELETE".equalsIgnoreCase(method) && servletPath.matches("/account/user/\\w+/?"))
				&& userAccount.getRoles().contains("Administrator".toUpperCase());
	}

	private boolean checkEndPoint(String method, String servletPath) {
		return ("DELETE".equalsIgnoreCase(method) && servletPath.matches("/account/user/\\w+/?"))
				|| ("PUT".equalsIgnoreCase(method) && servletPath.matches("/account/user/\\w+/?"))
				|| servletPath.matches("/account/password/?") || servletPath.matches("/forum/post/\\w+/?")
				|| ("PUT".equalsIgnoreCase(method) && servletPath.matches("/forum/post/\\w+/comment/\\w+/?"))
						&& !("GET".equalsIgnoreCase(method) && servletPath.matches("/forum/post/\\w+/?"));
	}

}
