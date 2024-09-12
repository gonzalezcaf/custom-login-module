package com.example.security;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;

public class CustomLdapLoginModule implements LoginModule {

    private static final Logger logger = Logger.getLogger(CustomLdapLoginModule.class.getName());

    private Subject subject;
    private CallbackHandler callbackHandler;
    private Map<String, ?> sharedState;
    private Map<String, ?> options;
    private boolean loginSucceeded = false;
    private String username;
    private String password;

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options) {
        this.subject = subject;
        this.callbackHandler = callbackHandler;
        this.sharedState = sharedState;
        this.options = options;
    }

    @Override
    public boolean login() throws LoginException {
        logger.log(Level.INFO, "Iniciando login en CustomLdapLoginModule");

        NameCallback nameCallback = new NameCallback("Username: ");
        PasswordCallback passwordCallback = new PasswordCallback("Password: ", false);
        Callback[] callbacks = new Callback[]{nameCallback, passwordCallback};

        try {
            callbackHandler.handle(callbacks);
            username = nameCallback.getName();
            password = new String(passwordCallback.getPassword());
        } catch (Exception e) {
            throw new LoginException("Error en el manejo de las credenciales: " + e.getMessage());
        }

        // Simulación de autenticación en LDAP
        if (authenticateWithLdap(username, password)) {
            loginSucceeded = true;
            return true;
        } else {
            throw new LoginException("Autenticación fallida para el usuario: " + username);
        }
    }

    @Override
    public boolean commit() throws LoginException {
        if (!loginSucceeded) {
            return false;
        }

        subject.getPrincipals().add(new UserPrincipal(username));

        List<String> roles = getRolesFromLdap(username);
        for (String role : roles) {
            subject.getPrincipals().add(new RolePrincipal(role));
        }

        logger.log(Level.INFO,"Roles retornados del commit(): " + roles);
        return true;
    }

    @Override
    public boolean abort() throws LoginException {
        if (!loginSucceeded) {
            return false;
        }

        logout();
        return true;
    }

    @Override
    public boolean logout() throws LoginException {
        subject.getPrincipals().clear();
        return true;
    }

    private boolean authenticateWithLdap(String username, String password) {
        // Aquí se agregaría la lógica de autenticación contra LDAP
        return "admin".equals(username) && "redhat01".equals(password);
    }

    private List<String> getRolesFromLdap(String username) {
        // Simulación de roles obtenidos de LDAP
        List<String> roles = new ArrayList<>();
        if ("admin".equals(username)) {
            roles.add("AuthenticatedPerson");
        }
        logger.log(Level.INFO, "Roles retornados: " + roles);
        return roles;
    }

    public static class UserPrincipal implements java.security.Principal {
        private String name;

        public UserPrincipal(String name) {
            this.name = name;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public String toString() {
            return "UserPrincipal{name='" + name + "'}";
        }
    }

    public static class RolePrincipal implements java.security.Principal {
        private String role;

        public RolePrincipal(String role) {
            this.role = role;
        }

        @Override
        public String getName() {
            return role;
        }

        @Override
        public String toString() {
            return "RolePrincipal{role='" + role + "'}";
        }
    }
}
