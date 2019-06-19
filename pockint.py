#!/usr/bin/env python

import datetime
import tkinter as tk
from tkinter import messagebox
import tkinter.ttk as ttk
from utils import InputValidator, Database, load_icon, callback

__version__ = '1.0.0'

class CreditsTool(tk.Toplevel):
    """Opens a new window providing credits"""

    def __init__(self, master=None, *args, **kwargs):
        """Initializes Toplevel object and builds credit interface."""
        super().__init__(master, *args, **kwargs)
        # hide window in background during drawing and load, to prevent flickering and glitches as per
        # https://stackoverflow.com/questions/48492273/preloading-windows-to-avoid-tkinter-visual-glitches-during-frame-load
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

class ApiTool(tk.Toplevel):
    """Opens a new window providing users ability to input api keys"""

    def __init__(self, master=None, *args, **kwargs):
        """Initializes Toplevel object and builds credit interface."""
        super().__init__(master, *args, **kwargs)
        self.db_handler = Database()
        # hide window in background during drawing and load, to prevent flickering and glitches as per
        # https://stackoverflow.com/questions/48492273/preloading-windows-to-avoid-tkinter-visual-glitches-during-frame-load
        self.withdraw()
        # build and draw the window
        self.build()
        # unhide the Toplevel window immediately after draw and load 
        self.after(0, self.deiconify)

    def build(self):
        """Initializes and builds application widgets."""
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
        self.icon = load_icon()
        self.build_menu()
        self.build_interface()
        self.id_tracker = dict()
    
    def build_menu(self):
        """Initializes and builds program menu bar"""
        self.top = tk.Menu(self)

        # create run menu
        self.run = tk.Menu(self.top, tearoff=False)
        self.run.add_command(label='Search', accelerator='Ctrl+S',
                              command=self.run_data_mining, compound=tk.LEFT, underline=0)
        self.run.add_separator()
        self.run.add_command(label='Exit', command=self.quit_program,
                              underline=0)
        self.top.add_cascade(label='Run', menu=self.run, underline=0)

        # create edit menu
        self.edit = tk.Menu(self.top, tearoff=False)
        self.edit.add_command(label='API keys', command=self.manage_apis,
                              compound=tk.LEFT, underline=0)
        self.top.add_cascade(label='Edit', menu=self.edit, underline=0)

        # create about menu
        self.info = tk.Menu(self.top, tearoff=False)
        self.info.add_command(label='About ...', command=self.view_credits,
                              compound=tk.LEFT, underline=0)
        self.top.add_cascade(label='?', menu=self.info, underline=0)

        self.run.entryconfig("Search", state="disabled")

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
        self.selector.bind("<<ComboboxSelected>>", self.run_data_mining)
        self.selector.bind("<Return>", self.run_data_mining)
        self.treeview.bind('<ButtonRelease-1>', self.selectItem)

        # focus on entry widget
        self.entry.focus()

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
                self.run.entryconfig("Search", state="active")
            else:
                self.selector["values"] = [""]
                self.selector.set("")
                self.run.entryconfig("Search", state="disabled")
                self.status['text'] = "input: invalid"
        elif not _input:
            self.status['text'] = "ready"
            self.selector["values"] = [""]
            self.run.entryconfig("Search", state="disabled")
            self.selector.current(0)

    def run_data_mining(self, event=None):
        """Performs the select OSINT data mining operation"""
        self.status['text'] = "running..."
        _input = self.entry.get().split(",")
        transform = self.selector.get()
        try:
            for i in _input:
                data = self.validator.execute_transform(i, transform)
                for item in data:
                    self.treeview.insert(self.getID(i), "end", values=(transform, item))
            # todo: focus on last treeview output to be able to hit enter and iterate
            # item = self.treeview.insert('', 'end', text=_input, values=(transform, data))
            # self.treeview.focus_set()
            # self.treeview.selection_set(item)
            self.entry.focus()
            self.status['text'] = "ready"
        except Exception as e:
            messagebox.showerror("Error", "Error message:" + str(e))
    
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
        self.win_credits.title('')
        self.win_credits.geometry('+%d+%d' % (root.winfo_x() +
                                              20, root.winfo_y() + 20))
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
        self.api_tool.title('')
        self.api_tool.geometry('+%d+%d' % (root.winfo_x() +
                                              20, root.winfo_y() + 20))
        self.api_tool.iconbitmap(self.icon)
        self.api_tool.resizable(width=False, height=False)
        self.api_tool.protocol('WM_DELETE_WINDOW', self.api_tool.close_window)
        # set focus on window
        self.api_tool.grab_set()
        self.api_tool.focus()

        # start mainloop
        self.api_tool.mainloop()

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
    root.iconbitmap(pockint.icon)
    root.protocol('WM_DELETE_WINDOW', pockint.quit_program)
    root.mainloop()