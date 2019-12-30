#!/usr/bin/env python

import datetime
from threading import Thread
import tkinter as tk
from tkinter import messagebox
import tkinter.ttk as ttk
from utils import InputValidator, Database, load_icon, callback
import sys

__version__ = '1.2.0'

class CreditsTool(tk.Toplevel):
    """Opens a new window providing credits"""

    def __init__(self, master=None, *args, **kwargs):
        """Initializes Toplevel object and builds credit interface."""
        super().__init__(master, *args, **kwargs)
        # hide window in background during drawing and load, to prevent flickering and glitches during frame load
        self.withdraw()
        # build and draw the window
        self.build()
        # unhide the Toplevel window immediately after draw and load 
        self.after(0, self.deiconify)

    def build(self):
        """Initializes and builds application widgets."""
        text_credits = 'POCKINT\nversion {ver}\n copyright © {year}' \
                       ''.format(year=datetime.datetime.now().year,
                                      ver=__version__)
        author_info = "Written with ♥ by\nNetEvert"

        # create main credits label
        self.lbl_info = tk.Label(self, text=text_credits,
                                 font=('courier', 10, 'normal'))
        self.lbl_author = tk.Label(self, text=author_info,
                                 font=('courier', 10, 'normal'), cursor="hand2")

        self.lbl_info.grid(row=0, column=0, sticky='w', padx=1, pady=1)
        self.lbl_author.grid(row=1, column=0, sticky='w', padx=1, pady=1)
        self.lbl_author.bind("<Button-1>", lambda e: callback("https://twitter.com/netevert"))

class SaveTool(tk.Toplevel):
    """Opens a window to store investigation data"""
    def __init__(self, master=None, investigation_id=None, data=None, *args, **kwargs):
        """Initializes Toplevel object and builds interface"""
        super().__init__(master, *args, **kwargs)
        # initialize variables
        self.investigation_id = investigation_id
        self.data = data
        # initialize database
        self.db_handler = Database()
        # hide window in background during drawing and load, to prevent flickering and glitches during frame load
        self.withdraw()
        # build and draw the window
        self.build()
        # unhide the Toplevel window immediately after draw and load 
        self.after(0, self.deiconify)

    def build(self):
        """Initializes and builds application widgets"""
        # create input labelframe
        labelframe_1 = tk.LabelFrame(self, fg='brown')
        labelframe_1.pack(side="top", expand='yes', fill='both', padx=2, pady=2, anchor="n")

        # create explanation label
        self.label = tk.Label(labelframe_1, text='Save As...')
        self.label.pack(expand=True, fill='x', side="left", padx=2, pady=2)

        # create data input entry widget
        self.entry = tk.Entry(labelframe_1)
        self.entry.pack(expand=True, fill='x', side="left", padx=2, pady=2)
        
        # create save button
        self.save_button = tk.Button(labelframe_1, text="Save", command=self.save_data)
        self.save_button.pack(expand=False, side="left", padx=2, pady=2, anchor="e")

        # create cancel button
        self.cancel_button = tk.Button(labelframe_1, text="Cancel", command=self.quit_save)
        self.cancel_button.pack(expand=False, side="left", padx=2, pady=2, anchor="e")

        self.entry.insert(0, self.investigation_id)

    def save_data(self):
        """Stores investigation data within database"""
        if self.data:
            try:
                self.db_handler.store_investigation(self.entry.get(), self.data)
                messagebox.showinfo("Success", "Successfully saved investigation")
                self.quit_save()

            except Exception:
                messagebox.showerror("Error saving data", "Failed to save data!")
                self.quit_save()
        else:
            messagebox.showinfo("No data", "There is no data to save")

    def quit_save(self):
        """Quits the save window"""
        self.db_handler.close_connection()
        self.destroy()

class OpenTool(tk.Toplevel):
    """Opens a window to retrieve investigation data"""
    def __init__(self, master=None, *args, **kwargs):
        """Initializes Toplevel object and builds interface"""
        super().__init__(master, *args, **kwargs)
        # initialize variables
        self.selection = tk.StringVar(self)
        # initialize database
        self.db_handler = Database()
        # hide window in background during drawing and load, to prevent flickering and glitches during frame load
        self.withdraw()
        # build and draw the window
        self.build()
        # unhide the Toplevel window immediately after draw and load 
        self.after(0, self.deiconify)

    def build(self):
        """Initializes and builds application widgets"""
        # create input labelframe
        labelframe_1 = tk.LabelFrame(self, fg='brown')
        labelframe_1.pack(side="top", expand='yes', fill='both', padx=2, pady=2, anchor="n")

        # create explanation label
        self.label = tk.Label(labelframe_1, text='Load...')
        self.label.pack(expand=True, fill='x', side="left", padx=2, pady=2)

        # create data input entry widget
        self.options = tk.OptionMenu(labelframe_1, self.selection, *self.db_handler.retrieve_investigation_ids(),
        command=self.open_data)
        self.options.pack(expand=True, fill='x', side="left", padx=2, pady=2)
        self.selection.set(self.db_handler.retrieve_investigation_ids()[0])

        # create save button
        self.save_button = tk.Button(labelframe_1, text="Open", command=self.open_data)
        self.save_button.pack(expand=False, side="left", padx=2, pady=2, anchor="e")

        # create cancel button
        self.cancel_button = tk.Button(labelframe_1, text="Cancel", command=self.quit_open)
        self.cancel_button.pack(expand=False, side="left", padx=2, pady=2, anchor="e")

    def open_data(self, value=None):
        """Retrieves investigation data from database"""
        pockint.treeview.delete(*pockint.treeview.get_children())
        pockint.id_tracker = {}
        if value:
            investigation_id = value
        else:
            investigation_id = self.selection.get()
        try:
            iid, data = self.db_handler.open_investigation(investigation_id)
            for target in data:
                for transform in data[target]:
                    pockint.treeview.insert(pockint.getID(target), "end", values=(transform[0], transform[1]))
            pockint.investigation_id_tracker = iid
            self.quit_open()

        except Exception as e:
            print("[*] Error: ", e)
            self.quit_open()

    def quit_open(self):
        """Quits the open window"""
        self.db_handler.close_connection()
        self.destroy()

class DeleteTool(tk.Toplevel):
    """Opens a window to retrieve investigation data"""
    def __init__(self, master=None, *args, **kwargs):
        """Initializes Toplevel object and builds interface"""
        super().__init__(master, *args, **kwargs)
        # initialize variables
        self.selection = tk.StringVar(self)
        # initialize database
        self.db_handler = Database()
        # hide window in background during drawing and load, to prevent flickering and glitches during frame load
        self.withdraw()
        # build and draw the window
        self.build()
        # unhide the Toplevel window immediately after draw and load 
        self.after(0, self.deiconify)

    def build(self):
        """Initializes and builds application widgets"""
        # create input labelframe
        labelframe_1 = tk.LabelFrame(self, fg='brown')
        labelframe_1.pack(side="top", expand='yes', fill='both', padx=2, pady=2, anchor="n")

        # create explanation label
        self.label = tk.Label(labelframe_1, text='Delete...')
        self.label.pack(expand=True, fill='x', side="left", padx=2, pady=2)

        # create data input entry widget
        self.options = tk.OptionMenu(labelframe_1, self.selection, *self.db_handler.retrieve_investigation_ids(),
        command=self.delete_data)
        self.options.pack(expand=True, fill='x', side="left", padx=2, pady=2)
        self.selection.set(self.db_handler.retrieve_investigation_ids()[0])

        # create save button
        self.save_button = tk.Button(labelframe_1, text="Delete", command=self.delete_data)
        self.save_button.pack(expand=False, side="left", padx=2, pady=2, anchor="e")

        # create cancel button
        self.cancel_button = tk.Button(labelframe_1, text="Cancel", command=self.quit)
        self.cancel_button.pack(expand=False, side="left", padx=2, pady=2, anchor="e")

    def delete_data(self, value=None):
        """Deletes investigation data from database"""
        if value:
            investigation_id = value
        else:
            investigation_id = self.selection.get()
        try:
            self.db_handler.delete_investigation(investigation_id)
            self.quit()

        except Exception as e:
            print("[*] Error: ", e)
            self.quit()

    def quit(self):
        """Quits the open window"""
        self.db_handler.close_connection()
        self.destroy()

class ApiTool(tk.Toplevel):
    """Opens a new window providing users ability to input api keys"""

    def __init__(self, master=None, *args, **kwargs):
        """Initializes Toplevel object and builds interface"""
        super().__init__(master, *args, **kwargs)
        self.db_handler = Database()
        # hide window in background during drawing and load, to prevent flickering and glitches during frame load
        self.withdraw()
        # build and draw the window
        self.build()
        # unhide the Toplevel window immediately after draw and load 
        self.after(0, self.deiconify)

    def build(self):
        """Initializes and builds application widgets"""
        # create input labelframe
        labelframe_1 = tk.LabelFrame(self, text="api key manager", fg='brown')
        labelframe_1.pack(side="top", expand='yes', fill='both', padx=2, pady=2, anchor="n") 
        
        # create data mining action selection drop down
        self.selector = ttk.Combobox(labelframe_1, values=self.db_handler.get_apis(), state="readonly", width=50)
        self.selector.current(0)
        self.selector.pack(expand=True, fill='x', side="top", padx=2, pady=2)

        # create data input entry widget
        self.entry = tk.Entry(labelframe_1)
        self.entry.pack(expand=True, fill='x', side="top", padx=2, pady=2)

        # create status label
        self.status = tk.Label(self, text='hit return to store api key', font=('verdana', 6, 'normal'))
        self.status.pack(anchor='se')

        # gui bindings
        self.selector.bind("<<ComboboxSelected>>", self.grab_api_key)
        self.selector.bind("<Return>", self.grab_api_key)
        self.entry.bind('<Return>', self.add_api_key)

    def grab_api_key(self, event=None):
        """Returns api key of selected api"""
        api = self.selector.get()
        _key = self.db_handler.get_api_key(api)
        self.entry.delete(0, tk.END)
        self.entry.insert(0, _key)
        self.status['text'] = "api key retrieved"
        if not _key:
            self.status['text'] = "no api key exists, create one?"

    def add_api_key(self, event=None):
        """Adds api key in database"""
        _key = self.entry.get()
        if self.entry.get():
            self.db_handler.insert_api_key(self.selector.get(), self.entry.get())
            self.grab_api_key()
            self.status['text'] = "api key added"
        if not self.entry.get():
            if self.db_handler.get_api_key(self.selector.get()):
                self.db_handler.insert_api_key(self.selector.get(), self.entry.get())
                self.grab_api_key()
                self.status['text'] = "api key deleted"
            else:
                self.status['text'] = "no api key provided"

    def close_window(self):
        """Closes program window and database"""
        self.db_handler.close_connection()
        self.destroy()

class Gui(tk.Frame):
    """Main program graphical user interface"""
    def __init__(self, master=None, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        if sys.platform == "win32":
            self.icon = load_icon()
        self.multi_select = tk.BooleanVar()
        self.build_menu()
        self.build_interface()
        self.id_tracker = dict()
        self.transforms_tracker = set()
        self.investigation_id_tracker = ""
    
    def build_menu(self):
        """Initializes and builds program menu bar"""
        self.top = tk.Menu(self)

        # create file menu
        self.file = tk.Menu(self.top, tearoff=False)
        self.file.add_command(label="Load investigation...", compound=tk.LEFT, underline=0, command=self.open_investigation)
        self.file.add_command(label="Save investigation...", compound=tk.LEFT, underline=0, command=self.save_investigation)
        self.file.add_command(label="Delete investigation...", compound=tk.LEFT, underline=0, command=self.delete_investigation)
        self.file.add_separator()
        self.file.add_command(label='Exit', command=self.quit_program,
                              underline=0)

        self.top.add_cascade(label="File", menu=self.file, underline=0)

        # create edit menu
        self.edit = tk.Menu(self.top, tearoff=False)
        self.edit.add_command(label="Clear data", compound=tk.LEFT, underline=0, command=self.clear_investigation_data)
        self.edit.add_separator()
        self.edit.add_command(label='API keys', command=self.manage_apis,
                              compound=tk.LEFT, underline=0)
        self.top.add_cascade(label='Edit', menu=self.edit, underline=0)

        # create run menu
        self.run = tk.Menu(self.top, tearoff=False)
        self.run.add_checkbutton(label="Multi-Select", onvalue=True, offvalue=False, variable=self.multi_select, command=self.config_menu)
        self.run.add_command(label='Run Transform', accelerator='Ctrl+R',
                              command=self.run_data_mining, compound=tk.LEFT, underline=0)
        
        self.top.add_cascade(label='Run', menu=self.run, underline=0)

        # create about menu
        self.info = tk.Menu(self.top, tearoff=False)
        self.info.add_command(label='About ...', command=self.view_credits,
                              compound=tk.LEFT, underline=0)
        self.top.add_cascade(label='?', menu=self.info, underline=0)

        self.run.entryconfig("Run Transform", state="disabled")

    def build_interface(self):
        """Builds the gui interface"""
        # create search frame
        frame_1 = tk.Frame()
        frame_1.pack(expand=False, fill='x', anchor="n")
        
        # create input labelframe
        labelframe_1 = tk.LabelFrame(frame_1, text="input", fg='brown')
        labelframe_1.pack(side="top", expand='yes', fill='both', padx=2, pady=2, anchor="n") 
        
        # create data input entry widget
        self.entry = tk.Entry(labelframe_1)
        self.entry.pack(expand=True, fill='x', side="top", padx=2, pady=2)
        
        # create data mining action selection drop down
        self.selector = ttk.Combobox(labelframe_1, values=[""], state="readonly")
        self.selector.pack(expand=True, fill='x', side="top", padx=2, pady=2)

        # create results frame
        frame_2 = tk.Frame()
        frame_2.pack(expand=True, fill='both', anchor="n")
        
        # create output labelframe
        labelframe_2 = tk.LabelFrame(frame_2, text="osint", padx=2, pady=2, fg='brown')
        labelframe_2.pack(side="top", expand='yes', fill='both', padx=2, pady=2)
        
        # create results treeview and associated scrollbar
        self.treeview = ttk.Treeview(labelframe_2, column=('A', 'B'),
                                 selectmode='extended', height=5)
        self.treeview.pack(expand=1, fill='both', side=tk.LEFT)
        self.treeview.column("#0", width=130)
        self.treeview.heading("#0", text='input')
        self.treeview.column("A", width=130)
        self.treeview.heading("A", text='osint')
        self.treeview.column("B", width=130)
        self.treeview.heading("B", text="output")
        self.sbar = tk.Scrollbar(labelframe_2)
        self.treeview.config(yscrollcommand=self.sbar.set)
        self.sbar.config(command=self.treeview.yview)
        self.sbar.pack(expand='no', fill='both', side=tk.LEFT, anchor="e")
        
        # create status label
        self.status = tk.Label(frame_2, text='ready', font=('verdana', 6, 'normal'))
        self.status.pack(anchor='se')

        # gui bindings
        self.entry.bind('<Return>', self.validate_input)
        self.entry.bind('<FocusOut>', self.validate_input)
        self.selector.bind("<<ComboboxSelected>>", self.run_data_mining)
        self.selector.bind("<Return>", self.run_data_mining)
        self.selector.bind("<ButtonRelease-1>", self.config_menu)
        self.treeview.bind('<ButtonRelease-1>', self.selectItem)
        self.bind_all('<Control-r>', self.run_data_mining)

        # focus on entry widget
        self.entry.focus()

    def config_menu(self, event=None):
        """Ensures search menu option is properly enabled and disabled"""
        if self.multi_select.get():
            self.run.entryconfig("Run Transform", state="disabled")
        elif self.selector.get() == "":
            self.run.entryconfig("Run Transform", state="disabled")
        else:
            self.run.entryconfig("Run Transform", state="active")

    def validate_input(self, event=None):
        """Validates and sanitizes user input"""
        self.validator = InputValidator()
        _input = self.entry.get()
        if _input:
            validated_input = self.validator.validate(_input)[-1:][0]
            if validated_input[0]:
                self.status['text'] = validated_input[1]
                self.selector['values'] = validated_input[2]
                self.selector.current(0)
                self.selector.focus()
                self.config_menu()
            else:
                self.selector["values"] = [""]
                self.selector.set("")
                self.run.entryconfig("Run Transform", state="disabled")
                self.status['text'] = "input: invalid"
        elif not _input:
            self.status['text'] = "ready"
            self.selector["values"] = [""]
            self.run.entryconfig("Run Transform", state="disabled")
            self.selector.current(0)

    def run_data_mining(self, event=None):
        """Performs the select OSINT data mining operation"""
        self.finished = False
        if self.multi_select.get():
            self.transforms_tracker.add(self.selector.get())
            self.status['text'] = "multi-select: [{}]".format(" - ".join([transform for transform in self.transforms_tracker]))
        else:
            self.status['text'] = "running..."
            _input = self.entry.get().split(",")
            if _input[0]:
                transform = self.selector.get()
                self.transforms_tracker.add(transform)
                try:
                    t = Thread(target=self.run_transform, args=(_input, self.transforms_tracker,))
                    t.daemon = True
                    t.start()
                    self.check_status()
                    self.entry.focus()
                    self.status['text'] = "ready"
                    self.transforms_tracker.clear()
                except Exception as e:
                    messagebox.showerror("Error", "Error message:" + str(e))
            else:
                self.status['text'] = "no inputs"

    def run_transform(self, _input, transforms):
        """Run lisf of transforms on input data"""
        transform_executed = str
        try:
            for i in _input:
                for transform in transforms:
                    transform_executed = transform
                    data = self.validator.execute_transform(i, transform)
                    for item in data:
                        self.treeview.insert(self.getID(i), "end", values=(transform, item))
            self.finished = True
        except Exception as e:
            self.finished = True
            messagebox.showerror("Error", 
            "Error during transform [{}] \nError message: {}".format(transform_executed, str(e)))

    def check_status(self):
        """Checks if the transform thread has finished executing"""
        while self.finished is False:
            root.update()
    
    def getID(self, item):  
        """Grabs the ID of the queried treeview item"""
        if item in self.id_tracker.keys():
            return self.id_tracker[item]
        else:
            _id = self.treeview.insert('', "end", text=item)
            self.id_tracker[item] = _id
            return _id

    def selectItem(self, event=None):
        """Selects item in treeview and inserts in search box"""
        curItem = self.treeview.identify("item", event.x, event.y)
        self.entry.delete(0, 'end')
        try:
            if self.treeview.item(curItem)["text"]:
                self.entry.insert(0, self.treeview.item(curItem)["text"])
            self.entry.insert(0, self.treeview.item(curItem)["values"][1])
        except IndexError:
            pass
        self.validate_input()

    def view_credits(self):
        """Opens a new window providing credits information"""
        # launch window and configure window settings
        self.win_credits = CreditsTool()
        if sys.platform == "win32":
            self.win_credits.title('')
        else:
            self.win_credits.title('Credits')
        self.win_credits.geometry('+%d+%d' % (root.winfo_x() +
                                              20, root.winfo_y() + 20))
        self.win_credits.geometry("160x100")
        if sys.platform == "win32":
            self.win_credits.iconbitmap(self.icon)
        self.win_credits.resizable(width=False, height=False)
        # set focus on window
        self.win_credits.grab_set()
        self.win_credits.focus()

        # start mainloop
        self.win_credits.mainloop()

    def manage_apis(self):
        """Opens a new window allowing user to manage api keys"""
        # launch window and configure window settings
        self.api_tool = ApiTool()
        self.api_tool.title('Manage APIs')
        self.api_tool.geometry('+%d+%d' % (root.winfo_x() +
                                              20, root.winfo_y() + 20))
        if sys.platform == "win32":
            self.api_tool.iconbitmap(self.icon)
        self.api_tool.resizable(width=False, height=False)
        self.api_tool.protocol('WM_DELETE_WINDOW', self.api_tool.close_window)
        # set focus on window
        self.api_tool.grab_set()
        self.api_tool.focus()

        # start mainloop
        self.api_tool.mainloop()

    def grab_investigation_data(self):
        """"Stores investigation data"""
        data = {}
        for Parent in self.treeview.get_children():
            data[self.treeview.item(Parent)["text"]]=[]
            for child in self.treeview.get_children(Parent):
                if self.treeview.item(child)["values"] not in data[self.treeview.item(Parent)["text"]]:
                    data[self.treeview.item(Parent)["text"]].append(self.treeview.item(child)["values"])
        return data

    def save_investigation(self):
        """Saves investigation data"""
        if not self.investigation_id_tracker:
            self.investigation_id_tracker = datetime.datetime.now().strftime("%Y-%m-%d_%H:%M")
        data = self.grab_investigation_data()
        
        self.save = SaveTool(investigation_id=self.investigation_id_tracker, data=data)
        self.save.title('Save investigation')
        self.save.geometry('+%d+%d' % (root.winfo_x() +
                                              20, root.winfo_y() + 20))
        if sys.platform == "win32":
            self.save.iconbitmap(self.icon)
        self.save.resizable(width=False, height=False)
        self.save.protocol('WM_DELETE_WINDOW', self.save.quit_save)
        # set focus on window
        self.save.grab_set()
        self.save.focus()

        # start mainloop
        self.save.mainloop()
        
    def open_investigation(self):
        """Open investigation data"""
        db = Database()
        investigation_ids = db.retrieve_investigation_ids()
        if not investigation_ids:
            messagebox.showinfo("No saved investigations", "Please save an investigation before loading data")
            db.close_connection()
        if investigation_ids:
            # clear investigation id
            self.investigation_id_tracker = ""

            self.open = OpenTool()
            self.open.title('Open investigation')
            self.open.geometry('+%d+%d' % (root.winfo_x() +
                                                  20, root.winfo_y() + 20))
            if sys.platform == "win32":
                self.open.iconbitmap(self.icon)
            self.open.resizable(width=False, height=False)
            self.open.protocol('WM_DELETE_WINDOW', self.open.quit_open)
            # set focus on window
            self.open.grab_set()
            self.open.focus()

            # start mainloop
            self.open.mainloop()

    def delete_investigation(self):
        """Delete investigation data"""
        self.delete = DeleteTool()
        self.delete.title('Delete investigation')
        self.delete.geometry('+%d+%d' % (root.winfo_x() +
                                              20, root.winfo_y() + 20))
        if sys.platform == "win32":
            self.delete.iconbitmap(self.icon)
        self.delete.resizable(width=False, height=False)
        self.delete.protocol('WM_DELETE_WINDOW', self.delete.quit)
        # set focus on window
        self.delete.grab_set()
        self.delete.focus()

        # start mainloop
        self.delete.mainloop()

    def clear_investigation_data(self, event=None):
        """Clears investigation data from treeview"""
        self.treeview.delete(*pockint.treeview.get_children())
        self.id_tracker = {}
        self.entry.delete(0, "end")
        self.validate_input()

    @staticmethod
    def quit_program():
        """Quits main program window"""
        root.destroy()

if __name__ == '__main__':
    root = tk.Tk()
    root.title("POCKINT v.{}".format(__version__))
    pockint = Gui(root)
    root.config(menu=pockint.top)
    pockint.pack(expand=False)
    if sys.platform == "win32":
        root.iconbitmap(pockint.icon)
    root.protocol('WM_DELETE_WINDOW', pockint.quit_program)
    root.mainloop()
