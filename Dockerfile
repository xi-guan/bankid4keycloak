FROM quay.io/keycloak/keycloak:18.0.2-legacy
ADD target/bankid4keycloak-1.0.0-SNAPSHOT.jar /opt/jboss/keycloak/standalone/deployments/
