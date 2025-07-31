import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
import os
import re
from datetime import datetime
import webbrowser
import time
from PIL import Image, ImageTk   # Make sure you have Pillow installed

# Static platform options
PLATFORMS = ["Sentinel", "Splunk", "CrowdStrike", "Chronicle (YARA-L)", "YARA", "Sigma"]

# Global in-memory data store
rules = []
current_rule = None
json_file = "detection_rules.json"

# Utility: generate ID from title and timestamp
def generate_detection_id(title):
    slug = re.sub(r'[^a-z0-9]+', '-', title.lower()).strip('-')
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    return f"{slug}-{timestamp}"

# Load rules from file
def load_rules():
    global rules
    if os.path.exists(json_file):
        with open(json_file, 'r') as f:
            rules = json.load(f)

# Save rules to file
def save_rules():
    with open(json_file, 'w') as f:
        json.dump(rules, f, indent=2)

# Main App
class DetectionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("GhostTrace")
        root.iconbitmap("ghosttrace_logo.ico")
        # Add a top-level menu
        menu_bar = tk.Menu(self.root)
        self.root.config(menu=menu_bar)
        # File menu
        file_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Import Rules", command=self.import_rules)
        file_menu.add_command(label="Export All", command=self.export_all_rules)
        file_menu.add_separator()
        file_menu.add_command(label="Backup Rules", command=self.backup_rules)
        file_menu.add_command(label="Restore from Backup", command=self.restore_from_backup)
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)

        self.username = os.getlogin()

        load_rules()
        #new
        self.filtered_rules = []

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True)

        self.create_home_tab()
        self.create_add_content_tab()
        self.create_search_tab()

        self.refresh_search_results()

    def update_stats_label(self):
        rule_count = len(rules)
        try:
            last_modified = datetime.fromtimestamp(os.path.getmtime(json_file)).strftime("%Y-%m-%d %H:%M")
        except FileNotFoundError:
            last_modified = "--/--/----"
        stats_text = f"🗂  Total Rules: {rule_count}     🕒  Last Modified: {last_modified}"
        self.stats_label.config(text=stats_text)

    def create_home_tab(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Home")

        logo_image = Image.open("ghosttrace_logo.png")
        logo_image = logo_image.resize((100, 100), Image.ANTIALIAS)  # Adjust size as needed
        self.logo_photo = ImageTk.PhotoImage(logo_image)  # Store reference on self to avoid GC

        logo_label = tk.Label(frame, image=self.logo_photo, bg="white")  # You can change bg if needed
        logo_label.pack(pady=(10, 0))

        ghosttrace_title = tk.Label(
            frame,
            text="GhostTrace",
            font=("Orbitron", 20, "bold"),  # Orbitron is sleek and cyber-style
            fg="#00bfff"  # Light neon blue
        )
        ghosttrace_title.pack(pady=(5, 0))

        home_title = tk.Label(frame, text="🛡️ Detection Rule Library", font=("Segoe UI", 16, "bold"))
        home_title.pack(pady=(10, 5))

        home_desc = tk.Label(frame, text="Store, edit, and search detection rules across multiple platforms.", font=("Segoe UI", 11))
        home_desc.pack(pady=(0, 10))

        platforms_label = tk.Label(frame, text="Supported Platforms:", font=("Segoe UI", 10, "underline"))
        platforms_label.pack()
        platforms_list = tk.Label(frame, text="✔ Sentinel   ✔ Splunk   ✔ CrowdStrike\n✔ Chronicle (YARA-L)  ✔ YARA     ✔ Sigma", font=("Segoe UI", 10))
        platforms_list.pack(pady=(0, 10))

        quick_tips_label = tk.Label(frame, text="Quick Navigation Tips:", font=("Segoe UI", 10, "underline"))
        quick_tips_label.pack()
        quick_tips = tk.Label(frame, text=(
            "• Use the Add Content tab to input or edit rules\n"
            "• Search Library lets you find rules by keyword, tag, or platform\n"
            "• Click a search result to load it for editing\n"
            ##"• Use the top menu to import/export rule sets"
            "• Use the Search tab to export rules to a .txt file"
        ), font=("Segoe UI", 10), justify="left")
        quick_tips.pack(pady=(0, 10))

        # Dynamic metadata placeholders
        self.stats_label = tk.Label(frame, text="", font=("Segoe UI", 9, "italic"))
        self.stats_label.pack(pady=(5, 10))

        # GitHub repo placeholder
        repo_link = tk.Label(frame, text="🔗 View on GitHub", font=("Segoe UI", 10, "underline"), fg="blue", cursor="hand2")
        repo_link.pack()
        repo_link.bind("<Button-1>", lambda e: webbrowser.open_new("https://github.com/blu0"))

        # Version & Credits
        version_label = tk.Label(frame, text="App Version: v1.0.0", font=("Segoe UI", 9))
        version_label.pack(pady=(15, 0))

        credits_label = tk.Label(frame, text="Created by blu0 • © 2025", font=("Segoe UI", 9, "italic"))
        credits_label.pack(pady=(0, 10))

        self.update_stats_label()

    def create_add_content_tab(self):
        self.add_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.add_tab, text="Add Content")

        self.fields = {}
        labels = ["Title", "Description", "Platform", "Query", "Tags", "References"]
        max_lengths = {"Title": 100, "Description": 500, "Query": 10000, "Tags": 500, "References": 1000}

        for i, label_text in enumerate(labels):
            label = tk.Label(self.add_tab, text=label_text)
            label.grid(row=i*2, column=0, sticky='nw', padx=10, pady=2)

            if label_text == "Platform":
                var = tk.StringVar()
                dropdown = ttk.Combobox(self.add_tab, textvariable=var, values=PLATFORMS, state="readonly")
                dropdown.grid(row=i*2+1, column=0, columnspan=2, sticky='we', padx=10)
                self.fields[label_text] = var
            else:
                if label_text == "Query":
                    height = 12  # or 10–15 depending on how large you want it
                elif label_text in ["Title", "Tags"]:
                    height = 2
                else:
                    height = 5
                entry = tk.Text(self.add_tab, height=height, width=100)
                entry.grid(row=i*2+1, column=0, columnspan=2, padx=10, pady=2, sticky='we')
                entry.config(wrap='word')
                self.fields[label_text] = entry

        button_frame = tk.Frame(self.add_tab)
        button_frame.grid(row=20, column=0, columnspan=2, pady=10)

        tk.Button(button_frame, text="Save", command=self.save_rule).pack(side="left", padx=5)
        tk.Button(button_frame, text="New/Clear", command=self.clear_form).pack(side="left", padx=5)

    def get_field_value(self, key):
        if key == "Platform":
            return self.fields[key].get()
        else:
            return self.fields[key].get("1.0", "end").strip()

    def save_rule(self):
        global current_rule
        
        title = self.get_field_value("Title")
        if not title:
            messagebox.showerror("Missing Field", "Title is required.")
            return

        rule = {
            "title": title,
            "description": self.get_field_value("Description"),
            "platform": self.get_field_value("Platform"),
            "query": self.get_field_value("Query"),
            "tags": self.get_field_value("Tags"),
            "references": self.get_field_value("References"),
            "created_by": self.username,
            "date_added": datetime.now().strftime("%Y-%m-%d")
        }

        if current_rule:
            rule["id"] = current_rule["id"]
            rules[:] = [r if r.get("id") != rule["id"] else rule for r in rules]
        else:
            rule["id"] = generate_detection_id(title)
            rules.append(rule)

        save_rules()
        self.update_stats_label()
        messagebox.showinfo("Saved", f"Detection rule saved as {rule['id']}")
        current_rule = rule
        self.refresh_search_results()

    def clear_form(self):
        global current_rule
        current_rule = None
        for k, widget in self.fields.items():
            if k == "Platform":
                widget.set("")
            else:
                widget.delete("1.0", "end")

    def create_search_tab(self):
        self.search_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.search_tab, text="Search Library")

        search_frame = tk.Frame(self.search_tab)
        search_frame.pack(fill='x', pady=5, padx=10)

        self.search_entry = tk.Entry(search_frame, width=50)
        self.search_entry.pack(side='left')

        tk.Button(search_frame, text="Search", command=self.search_rules).pack(side='left', padx=5)
        tk.Button(search_frame, text="Clear Results", command=self.clear_search_results).pack(side='left', padx=5)

        self.sort_option = tk.StringVar(value="Newest First")
        sort_menu = ttk.Combobox(search_frame, textvariable=self.sort_option, values=["Newest First", "Oldest First", "A–Z (Title)", "Z–A (Title)"], state="readonly")
        sort_menu.pack(side='left', padx=10)
        sort_menu.bind("<<ComboboxSelected>>", lambda e: self.refresh_search_results())

        self.search_status_var = tk.StringVar(value="Currently Displaying: All Rules")
        search_status_label = tk.Label(search_frame, textvariable=self.search_status_var, font=("Segoe UI", 9, "italic"))
        search_status_label.pack(side='left', padx=10)

        self.results_listbox = tk.Listbox(self.search_tab, height=25, width=120)
        self.results_listbox.pack(fill='both', expand=True, padx=10, pady=10)
        self.results_listbox.bind('<<ListboxSelect>>', self.load_selected_rule)

        tk.Button(self.search_tab, text="Export to TXT", command=self.export_to_txt).pack(pady=5)

    def search_rules(self):
        term = self.search_entry.get().strip().lower()
        filtered = [r for r in rules if term in json.dumps(r).lower()]
        if term:
            self.search_status_var.set(f"Currently Displaying: Search → \"{term}\"")
        else:
            self.search_status_var.set("Currently Displaying: All Rules")
        self.populate_results(filtered)

    def clear_search_results(self):
        self.search_entry.delete(0, 'end')
        self.search_status_var.set("Currently Displaying: All Rules")
        self.populate_results(rules)

    def sort_rules(self, rule_list):
        sort_by = self.sort_option.get()
        if sort_by == "Newest First":
            return sorted(rule_list, key=lambda x: x.get("date_added", ""), reverse=True)
        elif sort_by == "Oldest First":
            return sorted(rule_list, key=lambda x: x.get("date_added", ""))
        elif sort_by == "A–Z (Title)":
            return sorted(rule_list, key=lambda x: x.get("title", "").lower())
        elif sort_by == "Z–A (Title)":
            return sorted(rule_list, key=lambda x: x.get("title", "").lower(), reverse=True)
        return rule_list

    def populate_results(self, rule_list):
        self.results_listbox.delete(0, 'end')
        self.filtered_rules = self.sort_rules(rule_list)
        for r in self.filtered_rules:
            summary = f"{r['id']} ({r['platform']})"
            self.results_listbox.insert('end', summary)

    def refresh_search_results(self):
        self.populate_results(rules)

    def load_selected_rule(self, event):
        global current_rule
        selection = self.results_listbox.curselection()
        if not selection:
            return
        idx = selection[0]
        selected_id = self.results_listbox.get(idx).split()[0]
        for r in rules:
            if r["id"] == selected_id:
                current_rule = r
                break
        if current_rule:
            for k, widget in self.fields.items():
                if k == "Platform":
                    widget.set(current_rule.get(k.lower(), ""))
                else:
                    widget.delete("1.0", "end")
                    value = current_rule.get(k.lower(), "")
                    if k == "query":
                        value = value.replace("\\n", "\n")  # Decode escaped newlines
                    widget.insert("1.0", value)
            self.notebook.select(self.add_tab)

    def export_to_txt(self):
        if not self.filtered_rules:
            messagebox.showinfo("Nothing to Export", "There are no rules to export.")
            return
        export_text = "\n\n".join(json.dumps(r, indent=2) for r in self.filtered_rules)
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if path:
            with open(path, "w") as f:
                f.write(export_text)
            messagebox.showinfo("Exported", f"Exported {len(self.filtered_rules)} rules to {path}")
 
    def export_all_rules(self):
        export_text = "\n\n".join(json.dumps(r, indent=2) for r in rules)
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if path:
            with open(path, "w") as f:
                f.write(export_text)
            messagebox.showinfo("Exported", f"All rules exported to:\n{path}")
    
    def import_rules(self):
        path = filedialog.askopenfilename(filetypes=[("JSON Files", "*.json")])
        if not path:
            return
        try:
            with open(path, 'r') as f:
                incoming = json.load(f)
        except Exception as e:
            messagebox.showerror("Import Failed", f"Could not load file:\n{e}")
            return
        if not isinstance(incoming, list):
            messagebox.showerror("Invalid Format", "Imported file must be a JSON array of rules.")
            return
        imported_count = 0
        conflict_choice = None  # "yes" or "no"
        apply_to_all = False
        for rule in incoming:
            if "id" not in rule:
                continue
            existing = next((r for r in rules if r.get("id") == rule["id"]), None)
            if existing:
                if apply_to_all:
                    if conflict_choice == "yes":
                        rules[:] = [r if r.get("id") != rule["id"] else rule for r in rules]
                        imported_count += 1
                    continue
                else:
                    dialog = ConflictDialog(self.root, rule["id"])
                    self.root.wait_window(dialog.top)
                    if dialog.result == "yes":
                        rules[:] = [r if r.get("id") != rule["id"] else rule for r in rules]
                        imported_count += 1
                    elif dialog.result == "no":
                        pass  # skip
                    conflict_choice = dialog.result
                    apply_to_all = dialog.apply_to_all.get()
            else:
                rules.append(rule)
                imported_count += 1
        save_rules()
        self.refresh_search_results()
        self.update_stats_label()
        messagebox.showinfo("Import Complete", f"{imported_count} rules imported successfully.")

    def backup_rules(self):
        backup_dir = "backups"
        os.makedirs(backup_dir, exist_ok=True)
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        backup_path = os.path.join(backup_dir, f"detection_rules_backup_{timestamp}.json")
        try:
            with open(backup_path, "w") as f:
                json.dump(rules, f, indent=2)
            messagebox.showinfo("Backup Complete", f"Rules backed up to:\n{backup_path}")
        except Exception as e:
            messagebox.showerror("Backup Failed", f"Could not save backup:\n{e}")
    
    def restore_from_backup(self):
        backup_path = filedialog.askopenfilename(
            title="Select Backup File",
            initialdir="backups",
            filetypes=[("JSON Files", "*.json")]
        )
        if not backup_path:
            return
        try:
            with open(backup_path, "r") as f:
                restored = json.load(f)
            if not isinstance(restored, list):
                raise ValueError("Backup file must contain a list of rules.")
        except Exception as e:
            messagebox.showerror("Restore Failed", f"Could not load backup:\n{e}")
            return
        # Confirm overwrite
        confirm = messagebox.askyesno("Restore Confirmation", "This will overwrite the current rule set. Continue?")
        if not confirm:
            return
        global rules
        rules = restored
        save_rules()
        self.refresh_search_results()
        self.update_stats_label()
        messagebox.showinfo("Restore Complete", "Rules successfully restored from backup.")

class ConflictDialog:
    def __init__(self, parent, rule_id):
        self.result = None
        self.apply_to_all = tk.BooleanVar()

        self.top = tk.Toplevel(parent)
        self.top.title("Conflict Detected")
        self.top.grab_set()
        self.top.resizable(False, False)

        tk.Label(self.top, text=f"A rule with ID '{rule_id}' already exists.").pack(padx=20, pady=(15, 5))
        tk.Label(self.top, text="Do you want to overwrite it?").pack(padx=20, pady=(0, 10))

        tk.Checkbutton(
            self.top,
            text="Apply this choice to all remaining conflicts",
            variable=self.apply_to_all
        ).pack(pady=(0, 10))

        btn_frame = tk.Frame(self.top)
        btn_frame.pack(pady=(0, 15))

        tk.Button(btn_frame, text="Yes", width=10, command=self.yes).pack(side="left", padx=10)
        tk.Button(btn_frame, text="No", width=10, command=self.no).pack(side="left", padx=10)

        self.top.protocol("WM_DELETE_WINDOW", self.no)

    def yes(self):
        self.result = "yes"
        self.top.destroy()

    def no(self):
        self.result = "no"
        self.top.destroy()

# Launch
if __name__ == "__main__":
    root = tk.Tk()
    app = DetectionApp(root)
    root.mainloop()
