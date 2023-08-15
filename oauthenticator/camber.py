from .generic import GenericOAuthenticator

import os
import requests


class CamberOAuthenticator(GenericOAuthenticator):

    async def authenticate(self, handler, data=None):
        code = handler.get_argument("code")

        params = dict(
            redirect_uri=self.get_callback_url(handler),
            code=code,
            grant_type='authorization_code',
        )
        params.update(self.extra_params)

        headers = self._get_headers()

        token_resp_json = await self._get_token(headers, params)

        user_data_resp_json = await self._get_user_data(token_resp_json)

        if callable(self.username_key):
            name = self.username_key(user_data_resp_json)
        else:
            name = user_data_resp_json.get(self.username_key)
            if not name:
                self.log.error(
                    "OAuth user contains no key %s: %s",
                    self.username_key,
                    user_data_resp_json,
                )
                return

        user_info = {
            'name': name,
            'auth_state': self._create_auth_state(token_resp_json, user_data_resp_json),
        }

        if callable(self.claim_groups_key):
            groups = self.claim_groups_key(user_data_resp_json)
        else:
            groups = user_data_resp_json.get(self.claim_groups_key)

        if groups:
            # Add group information to auth_model
            user_info["groups"] = groups
            user_info["admin"] = self.check_user_in_groups(
                groups, self.admin_groups
            )

        return user_info
