from ldap3.core.exceptions import LDAPException

from microsoft_ad.actions_base import MicrosoftADAction
from microsoft_ad.models.action_models import (
    ResetPassUserArguments,
    UserAccountArguments,
)

# 512 is the default value for userAccountControl for enabled accounts
DEFAULT_UAC = 512


class ResetUserPasswordAction(MicrosoftADAction):
    name = "Reset Password"
    description = "Reset password with an rdp connection with an admin account"

    def run(self, arguments: ResetPassUserArguments):
        self.log(
            f"[ResetPassword] Starting password reset for user: {arguments.username}",
            level="info",
        )
        self.log(f"[ResetPassword] Search base (basedn): {arguments.basedn}", level="debug")

        user_query = self.search_userdn_query(arguments.username, arguments.basedn)
        self.log(
            f"[ResetPassword] search_userdn_query returned {len(user_query)} result(s)",
            level="debug",
        )

        if len(user_query) == 0:
            raise Exception(f"User not found: {arguments.username}")

        if len(user_query) > 1:
            raise Exception(f"Multiple users found with name: {arguments.username}, count: {len(user_query)}")

        user_dn = user_query[0][0]
        self.log(f"[ResetPassword] Resolved DN: {user_dn}", level="debug")
        self.log(
            f"[ResetPassword] Calling extend.microsoft.modify_password for DN: {user_dn}",
            level="debug",
        )

        try:
            self.client.extend.microsoft.modify_password(user_dn, arguments.new_password)
        except LDAPException as e:
            self.log(
                f"[ResetPassword] LDAPException during modify_password: {e}",
                level="error",
            )
            raise Exception(f"Failed to reset password for account {arguments.username}: {e}") from e

        self.log(
            f"[ResetPassword] modify_password LDAP result: {self.client.result}",
            level="debug",
        )

        if self.client.result.get("description") != "success":
            raise Exception(f"Password reset failed for {arguments.username}: {self.client.result.get('description')}")

        self.log(
            f"[ResetPassword] Password reset successful for user: {arguments.username}",
            level="info",
        )


class EnableUserAction(MicrosoftADAction):
    name = "Enable User"
    description = "Enable an Azure Active Directory user"

    def run(self, arguments: UserAccountArguments):
        self.log(
            f"[EnableUser] Starting enabling user account: {arguments.username}",
            level="info",
        )
        self.log(f"[EnableUser] Search base (basedn): {arguments.basedn}", level="debug")

        user_query = self.search_userdn_query(arguments.username, arguments.basedn)
        self.log(
            f"[EnableUser] search_userdn_query returned {len(user_query)} result(s)",
            level="debug",
        )

        if len(user_query) == 0:
            raise Exception(f"User not found: {arguments.username}")

        if len(user_query) > 1:
            raise Exception(f"Multiple users found with name: {arguments.username}, count: {len(user_query)}")

        uac_disabled = 2
        user_dn = user_query[0][0]
        current_uac = user_query[0][1] if user_query[0][1] is not None else DEFAULT_UAC

        self.log(f"[EnableUser] Resolved DN: {user_dn}", level="debug")
        self.log(
            f"[EnableUser] Current UAC: {current_uac} (binary: {bin(current_uac)})",
            level="debug",
        )

        new_uac = current_uac & ~uac_disabled
        self.log(
            f"[EnableUser] New UAC after clearing ACCOUNTDISABLE bit: {new_uac} (binary: {bin(new_uac)})",
            level="debug",
        )
        self.log(f"[EnableUser] Calling client.modify for DN: {user_dn}", level="debug")

        try:
            self.client.modify(user_dn, {"userAccountControl": [("MODIFY_REPLACE", new_uac)]}, None)
        except LDAPException as e:
            self.log(f"[EnableUser] LDAPException during modify: {e}", level="error")
            raise Exception(f"Failed to enable {arguments.username} account: {e}") from e

        self.log(f"[EnableUser] modify LDAP result: {self.client.result}", level="debug")

        if self.client.result.get("description") != "success":
            raise Exception(f"Enable action failed for {arguments.username}: {self.client.result.get('description')}")

        self.log(f"[EnableUser] User {arguments.username} enabled successfully", level="info")


class DisableUserAction(MicrosoftADAction):
    name = "Disable User"
    description = "Disable an Azure Active Directory user"

    def run(self, arguments: UserAccountArguments):
        self.log(
            f"[DisableUser] Starting disable action for user: {arguments.username}",
            level="info",
        )
        self.log(f"[DisableUser] Search base (basedn): {arguments.basedn}", level="debug")

        user_query = self.search_userdn_query(arguments.username, arguments.basedn)
        self.log(
            f"[DisableUser] search_userdn_query returned {len(user_query)} result(s)",
            level="debug",
        )

        if len(user_query) == 0:
            raise Exception(f"User not found: {arguments.username}")

        if len(user_query) > 1:
            raise Exception(f"Multiple users found with name: {arguments.username}, count: {len(user_query)}")

        uac_disabled = 2
        user_dn = user_query[0][0]
        current_uac = user_query[0][1] if user_query[0][1] is not None else DEFAULT_UAC

        self.log(f"[DisableUser] Resolved DN: {user_dn}", level="debug")
        self.log(
            f"[DisableUser] Current UAC: {current_uac} (binary: {bin(current_uac)})",
            level="debug",
        )

        new_uac = current_uac | uac_disabled
        self.log(
            f"[DisableUser] New UAC after setting ACCOUNTDISABLE bit: {new_uac} (binary: {bin(new_uac)})",
            level="debug",
        )
        self.log(f"[DisableUser] Calling client.modify for DN: {user_dn}", level="debug")

        try:
            self.client.modify(user_dn, {"userAccountControl": [("MODIFY_REPLACE", new_uac)]}, None)
        except LDAPException as e:
            self.log(f"[DisableUser] LDAPException during modify: {e}", level="error")
            raise Exception(f"Failed to disable {arguments.username} account: {e}") from e

        self.log(f"[DisableUser] modify LDAP result: {self.client.result}", level="debug")

        if self.client.result.get("description") != "success":
            raise Exception(f"Disable action failed for {arguments.username}: {self.client.result.get('description')}")

        self.log(
            f"[DisableUser] User {arguments.username} has been disabled successfully",
            level="info",
        )
