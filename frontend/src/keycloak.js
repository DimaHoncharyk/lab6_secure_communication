import Keycloak from "keycloak-js";

const keycloak = new Keycloak({
  url: "http://localhost:8081",
  realm: "oidc-lab",
  clientId: "lab-spa"
});

export default keycloak;
