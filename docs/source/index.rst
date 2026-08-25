pyobs-auth
##########

Shared Keycloak/OIDC authentication client for pyobs web services (`pyobs-archive
<https://github.com/pyobs/pyobs-archive>`_, `pyobs-portal
<https://github.com/pyobs/pyobs-portal>`_, and future services), so each one doesn't reimplement
OIDC discovery, token validation, and user mapping on its own.

Unlike the other repos in this section, *pyobs-auth* is a pip-installable Django app you add to
an existing service, not something you deploy on its own — see :doc:`installation`.

.. toctree::
   :maxdepth: 1

   installation
   configuration
   architecture
   api
   development
