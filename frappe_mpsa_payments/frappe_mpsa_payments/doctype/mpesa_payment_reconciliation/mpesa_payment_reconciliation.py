# Copyright (c) 2024, Navari Limited and contributors
# For license information, please see license.txt

import frappe
from frappe.model.document import Document


class MpesaPaymentReconciliation(Document):

	_table_fieldnames = []

	def save(self):
		return
	
	def db_insert(self, *args, **kwargs):
		pass

	def load_from_db(self):
		pass

	def db_update(self):
		pass

	def delete(self):
		pass

	@staticmethod
	def get_list(args):
		pass

	@staticmethod
	def get_count(args):
		pass

	@staticmethod
	def get_stats(args):
		pass

