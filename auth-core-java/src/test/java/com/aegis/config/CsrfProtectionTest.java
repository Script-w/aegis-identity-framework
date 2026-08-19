package com.aegis.config;

import com.aegis.controller.AuthController;
import com.aegis.controller.CsrfController;
import com.aegis.security.JwtAuthenticationFilter;
import com.aegis.security.JwtService;
import com.aegis.service.AuthService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import com.jayway.jsonpath.JsonPath;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@WebMvcTest({AuthController.class, CsrfController.class})
@ContextConfiguration(classes = {
        AuthController.class,
        CsrfController.class,
        SecurityConfig.class,
        JwtAuthenticationFilter.class
})
class CsrfProtectionTest {
    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AuthService authService;

    @MockitoBean
    private JwtService jwtService;

    @Test
    void csrfEndpointBootstrapsCookieAndHeaderToken() throws Exception {
        mockMvc.perform(get("/api/auth/csrf"))
                .andExpect(status().isOk())
                .andExpect(cookie().exists("XSRF-TOKEN"))
                .andExpect(cookie().httpOnly("XSRF-TOKEN", false))
                .andExpect(jsonPath("$.headerName").value("X-XSRF-TOKEN"))
                .andExpect(jsonPath("$.token").isNotEmpty());
    }

    @Test
    void registrationWithoutCsrfTokenIsForbidden() throws Exception {
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content("{\"username\":\"alice\",\"password\":\"password\"}"))
                .andExpect(status().isForbidden());
    }

    @Test
    void registrationWithCsrfTokenReachesController() throws Exception {
        MvcResult bootstrap = mockMvc.perform(get("/api/auth/csrf"))
                .andExpect(status().isOk())
                .andReturn();
        jakarta.servlet.http.Cookie csrfCookie = bootstrap.getResponse().getCookie("XSRF-TOKEN");
        assertNotNull(csrfCookie);
        String csrfToken = JsonPath.read(bootstrap.getResponse().getContentAsString(), "$.token");

        mockMvc.perform(post("/api/auth/register")
                        .cookie(csrfCookie)
                        .header("X-XSRF-TOKEN", csrfToken)
                        .contentType(MediaType.APPLICATION_JSON_VALUE)
                        .content("{\"username\":\"alice\",\"password\":\"password\"}"))
                .andExpect(status().isOk());
    }
}
