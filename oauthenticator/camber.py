from .generic import GenericOAuthenticator

import os
import requests


class CamberOAuthenticator(GenericOAuthenticator):

    async def update_auth_model(self, auth_model):
        user_info = auth_model["auth_state"][self.user_auth_state_key]
        if callable(self.claim_groups_key):
            groups = self.claim_groups_key(user_info)
        else:
            groups = user_info.get(self.claim_groups_key)

        if groups:
            # Add group information to auth_model
            auth_model["groups"] = groups
            auth_model['admin'] = self.check_user_in_groups(
                groups, self.admin_groups
            )
        return auth_model

    def pre_spawn_start(self, user, spawner):
        auth_site_url = os.environ.get("AUTH_SITE_URL")
        auth_api_key = os.environ.get("AUTH_API_KEY")
        if auth_site_url and auth_api_key:
            user_groups = requests.get(
                f"{auth_site_url}/users/{user.name}/?key={auth_api_key}",
                verify=False
            ).json()
            groups = user_groups.get("groups")
            self.log.info(f"Collected groups for user {user.name}: {groups}")
            if groups and isinstance(groups, list):
                # N.B. Only support one group for now
                # TODO: Support multiple groups
                spawner.environment["CAMBER_GROUP"] = groups.pop(0)
        else:
            self.log.warning("No `AUTH_SITE_URL` or `AUTH_API_KEY` set for CamberHub")
