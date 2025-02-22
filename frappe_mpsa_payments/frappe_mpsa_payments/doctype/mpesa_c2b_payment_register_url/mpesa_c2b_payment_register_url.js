// Copyright (c) 2024, Navari Limited and contributors
// For license information, please see license.txt

frappe.ui.form.on("Mpesa C2B Payment Register URL", {
	refresh(frm) {
        frm.add_custom_button("Check Transaction Status", () => {
            frappe.prompt(
                [
                    {
                        label: "Transaction ID",
                        fieldname: "transaction_id",
                        fieldtype: "Data",
                        reqd: 1
                    },
                    {
                        label: "Remarks",
                        fieldname: "remarks",
                        fieldtype: "Small Text",
                    }
                ],
                (values) => {
                    frappe.call({
                        method: "trigger_transaction_status",
                        doc: frm.doc,
                        args: {
                            transaction_id: values.transaction_id,
                            remarks: values.remarks
                        },
                        callback: (r) => {
                            if (r.message) {
                                frappe.msgprint(r.message)
                            }
                        }
                    });
                },
                __("Transaction Status Query"),
                __("Submit")
            );
        });
	},
});
