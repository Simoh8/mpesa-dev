# Copyright (c) 2024, Frappe Technologies and contributors
# For license information, please see license.txt

from __future__ import unicode_literals
import frappe, requests
from frappe.model.document import Document
from frappe.utils import get_request_site_address
from frappe_mpsa_payments.frappe_mpsa_payments.api.m_pesa_api import get_token
from ..mpesa_settings.mpesa_connector import MpesaConnector
from frappe_mpsa_payments.utils.encoding_initiator_password import generate_security_credential

class MpesaC2BPaymentRegisterURL(Document):
    def validate(self):
        sandbox_url = "https://sandbox.safaricom.co.ke"
        live_url = "https://api.safaricom.co.ke"
        mpesa_settings = frappe.get_doc("Mpesa Settings", self.mpesa_settings)
        env = "production" if not mpesa_settings.sandbox else "sandbox"
        business_shortcode = (
            mpesa_settings.business_shortcode
            if env == "production"
            else mpesa_settings.till_number
        )
        if env == "sandbox":
            base_url = sandbox_url
        else:
            base_url = live_url

        token = get_token(
            app_key=mpesa_settings.consumer_key,
            app_secret=mpesa_settings.get_password("consumer_secret"),
            base_url=base_url,
        )

        site_url = get_request_site_address(True)
        validation_url = (
            #site_url + "/api/method/payments.payment_gateways.doctype.mpesa_c2b_payment_register_url.mpesa_api.validation"
            site_url + "/api/method/frappe_mpsa_payments.frappe_mpsa_payments.api.m_pesa_api.validation"
        )
        confirmation_url = (
            # site_url + "/api/method/payments.payment_gateways.doctype.mpesa_c2b_payment_register_url.mpesa_api.confirmation"
            site_url + "/api/method/frappe_mpsa_payments.frappe_mpsa_payments.api.m_pesa_api.confirmation"
        )
        register_url = base_url + "/mpesa/c2b/v2/registerurl"

        payload = {
            "ShortCode": business_shortcode,
            "ResponseType": "Completed",
            "ConfirmationURL": confirmation_url,
            "ValidationURL": validation_url,
        }
        headers = {
            "Authorization": "Bearer {0}".format(token),
            "Content-Type": "application/json",
        }

        try:
            r = requests.post(register_url, headers=headers, json=payload)
            r.raise_for_status()  # Raise an HTTPError for bad responses
            res = r.json()
            if res.get("ResponseDescription") == "Success":
                self.register_status = "Success"
            else:
                self.register_status = "Failed"
                frappe.msgprint(str(res))
        except requests.exceptions.HTTPError as errh:
            # Handle HTTP errors
            #frappe.msgprint(f"HTTP Error: {errh}")
            frappe.msgprint(f"Response Content: {errh.response.content}")
        except requests.exceptions.ConnectionError as errc:
            # Handle Connection errors
            frappe.msgprint(f"Error Connecting: {errc}")
        except requests.exceptions.Timeout as errt:
            # Handle Timeout errors
            frappe.msgprint(f"Timeout Error: {errt}")
        except requests.exceptions.RequestException as err:
            # Handle other exceptions
            frappe.msgprint(f"Request Exception: {err}")

    @frappe.whitelist()
    def trigger_transaction_status(self, transaction_id, remarks="OK"):

        try:

            settings = frappe.get_doc("Mpesa Settings", self.mpesa_settings)
            
            # Retrieve the public certificate path from the Mpesa Public Key Certificate doctype
            certificate_type = "sandbox_certificate" if settings.sandbox else "production_certificate"
            public_cert_path = frappe.db.get_single_value("Mpesa Public Key Certificate", certificate_type)

            if not public_cert_path:
                frappe.throw(f"Certificate file for {certificate_type} not found in Mpesa Public Key Certificate doctype.")

            # Generate security credential
            security_credential = generate_security_credential(settings.get_password("initiator_password"), public_cert_path)

            queue_timeout_url = get_request_site_address(True) + "/api/method/frappe_mpsa_payments.frappe_mpsa_payments.api.m_pesa_api.handle_queue_timeout"

            result_url = get_request_site_address(True) + "/api/method/frappe_mpsa_payments.frappe_mpsa_payments.api.m_pesa_api.handle_transaction_status_result"

            connector = MpesaConnector(
                env="production" if not settings.sandbox else "sandbox",
                app_key=settings.consumer_key,
                app_secret=settings.get_password("consumer_secret")
            )

            response = connector.transaction_status(
                initiator=settings.initiator_name,
                security_credential=security_credential,
                transaction_id=transaction_id,
                party_a=settings.business_shortcode if not settings.sandbox else settings.till_number,
                identifier_type=4,  # Assuming Organization Short Code
                remarks=remarks,
                occasion="",
                queue_timeout_url=queue_timeout_url,
                result_url=result_url
            )
            return response
        except Exception as e:
            frappe.log_error(title="Mpesa Transaction Status Error", message=str(e))
            return {"status": "error", "message": str(e)}
