API Reference
#############

Python API — this library has no REST API of its own, just the browser-facing views below.

KeycloakClient
**************
.. autoclass:: pyobs_auth.client.KeycloakClient
   :members:
   :show-inheritance:

.. autoclass:: pyobs_auth.client.AuthorizationRequest
   :members:

.. autoclass:: pyobs_auth.client.TokenExchangeError

TokenValidator
**************
.. autoclass:: pyobs_auth.validation.TokenValidator
   :members:
   :show-inheritance:

.. autoclass:: pyobs_auth.validation.TokenValidationError

KeycloakAuthentication
************************
.. autoclass:: pyobs_auth.authentication.KeycloakAuthentication
   :members:
   :show-inheritance:

``authorize()``
****************
.. autofunction:: pyobs_auth.authorization.authorize

KeycloakSessionRefreshMiddleware
*********************************
.. autoclass:: pyobs_auth.middleware.KeycloakSessionRefreshMiddleware
   :members:
   :show-inheritance:

Views
*****
.. autoclass:: pyobs_auth.views.LoginView
   :members:
   :show-inheritance:

.. autoclass:: pyobs_auth.views.CallbackView
   :members:
   :show-inheritance:

.. autoclass:: pyobs_auth.views.LogoutView
   :members:
   :show-inheritance:

Settings
********
.. autoclass:: pyobs_auth.settings.KeycloakSettings
   :members:

.. autoclass:: pyobs_auth.settings.ImproperlyConfiguredError
