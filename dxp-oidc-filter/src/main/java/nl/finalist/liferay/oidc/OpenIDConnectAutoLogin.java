package nl.finalist.liferay.oidc;


import com.liferay.portal.kernel.log.Log;
import com.liferay.portal.kernel.log.LogFactoryUtil;
import com.liferay.portal.kernel.module.configuration.ConfigurationProvider;
import com.liferay.portal.kernel.security.auto.login.AutoLogin;
import com.liferay.portal.kernel.security.auto.login.BaseAutoLogin;
import com.liferay.portal.kernel.service.UserLocalService;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.liferay.portal.kernel.util.HttpUtil;
import com.liferay.portal.kernel.util.PortalUtil;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;

/**
 * @see LibAutoLogin
 */
@Component(
    immediate = true,
    service = AutoLogin.class,
    configurationPid = "nl.finalist.liferay.oidc.OpenIDConnectOCDConfiguration"
)
public class OpenIDConnectAutoLogin extends BaseAutoLogin {

    private static final Log LOG = LogFactoryUtil.getLog(OpenIDConnectAutoLogin.class);

    @Reference
    private UserLocalService _userLocalService;

    private LibAutoLogin libAutologin;

    private ConfigurationProvider _configurationProvider;

    @Reference
    protected void setConfigurationProvider(ConfigurationProvider configurationProvider) {
        _configurationProvider = configurationProvider;
    }

    public OpenIDConnectAutoLogin() {
        super();
    }

    @Activate
    protected void activate() {
        libAutologin = new LibAutoLogin(new Liferay70Adapter(_userLocalService, _configurationProvider));
    }

    @Override
    protected String[] doLogin(HttpServletRequest request, HttpServletResponse response) throws Exception {
        try {
            String redirectName = "redirect";
            String sessionName = "LIFERAY_SHARED_REDIRECT_LOCATION";
            String currentURL = PortalUtil.getCurrentURL(request);
            LOG.info("doLogin currentURL: " + currentURL);
            String[] credentials = { "", "", "" };
            credentials = libAutologin.doLogin(request, response);
            if(credentials == null && currentURL.contains("login") && currentURL.contains(redirectName)) {
                String redirect = HttpUtil.getParameter(currentURL, redirectName);
                if(redirect == null || redirect.isEmpty()) {
                    redirect = parseParameter(currentURL, redirectName);
                }
                LOG.info("doLogin Saving redirect: " + redirect);
                // This seems to be saved on the IDP domain instead of liferays...
//                response.addCookie(new Cookie("redirect", redirect));
                request.getSession().setAttribute(sessionName, redirect);
            } else if(currentURL != null && currentURL.contains("login") && credentials != null &&
               credentials.length > 0 && credentials[0].length() > 0) {
                String redirect = PortalUtil.getPathMain();
                //User just signed in
//                 Cookie[] cookies = request.getCookies();
//                for (Cookie cookie : cookies) {
//                    if(cookie.getName().equals("redirect")) {
//                        redirect = cookie.getValue();
//                    }
//                }
                String redirectSession = request.getSession().getAttribute(sessionName).toString();
                if(redirectSession != null && !redirectSession.isEmpty()) {
                    redirect = HttpUtil.decodeURL(redirectSession);
                }
                request.setAttribute(AutoLogin.AUTO_LOGIN_REDIRECT, redirect);
                LOG.info("doLogin redirect: " + redirect);
            }
            return credentials;
        } catch(Exception err) {
            LOG.error("failed to doLogin", err);
            return new String[]{"", "", ""};
        }
    }

    private String parseParameter(String currentURL, String redirectName) {
        String value = "";
        if(currentURL == null || currentURL.isEmpty() || redirectName == null || redirectName.isEmpty()) {
            return value;
        }
        if(!currentURL.contains(redirectName)) {
            return value;
        }
        int lengthOfName = redirectName.length() + 1;
        int startOfParameterName = currentURL.indexOf(redirectName+"=");
        int endOfParameterName = startOfParameterName+lengthOfName;
        int endOfParameterValue = currentURL.indexOf("&", endOfParameterName);
        return currentURL.substring(endOfParameterName, endOfParameterValue);
    }

}
