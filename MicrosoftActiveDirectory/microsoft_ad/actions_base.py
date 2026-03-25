from ldap3.utils.conv import escape_filter_chars

from sekoia_automation.action import Action

from microsoft_ad.client.ldap_client import LDAPClient
from microsoft_ad.models.common_models import MicrosoftADModule


class MicrosoftADAction(Action, LDAPClient):
    module: MicrosoftADModule

    @property
    def client(self):
        return self.ldap_client

    def search_userdn_query(self, username, basedn):
        safe_username = escape_filter_chars(username)
        search_filter = f"(|(samaccountname={safe_username})(userPrincipalName={safe_username})(mail={safe_username})(givenName={safe_username}))"

        self.log(f"[search_userdn_query] Search base: {basedn}", level="debug")
        self.log(f"[search_userdn_query] Filter: {search_filter}", level="debug")
        self.log(
            f"[search_userdn_query] Attributes requested: cn, mail, userAccountControl",
            level="debug",
        )

        try:
            self.client.search(
                search_base=basedn,
                search_filter=search_filter,
                attributes=["cn", "mail", "userAccountControl"],
            )
        except Exception as e:
            self.log(
                f"[search_userdn_query] LDAP search raised ({type(e).__name__}): {e}",
                level="error",
            )
            raise Exception(f"LDAP search failed in base {basedn}: {e}") from e

        self.log(
            f"[search_userdn_query] Raw LDAP result: {self.client.result}",
            level="debug",
        )
        self.log(
            f"[search_userdn_query] Response entries count: {len(self.client.response)}",
            level="debug",
        )

        users_query = []

        for entry in self.client.response:
            if isinstance(entry, dict) and entry.get("type") == "searchResEntry":
                dn = entry.get("dn")
                user_attributes = entry.get("attributes", {})
                account_control: int | list[int] | None = user_attributes.get("userAccountControl")

                self.log(f"[search_userdn_query] Entry DN: {dn}", level="debug")
                self.log(
                    f"[search_userdn_query] userAccountControl raw value: {account_control!r}",
                    level="debug",
                )

                if dn and user_attributes.get("cn"):
                    account_control_final = None
                    if account_control is not None:
                        if isinstance(account_control, list):
                            account_control_final = int(account_control[0]) if len(account_control) > 0 else None
                        else:
                            account_control_final = account_control

                    self.log(
                        f"[search_userdn_query] Resolved UAC={account_control_final} for DN={dn}",
                        level="debug",
                    )
                    users_query.append([dn, account_control_final])
                else:
                    self.log(
                        f"[search_userdn_query] Entry skipped — dn={dn!r} cn={user_attributes.get('cn')!r}",
                        level="debug",
                    )

        self.log(
            f"[search_userdn_query] Finished — {len(users_query)} user(s) matched.",
            level="debug",
        )

        return users_query
