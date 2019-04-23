import tkinter as tk
from tkinter import messagebox
import tkinter.ttk as ttk
from utils import InputValidator

__version__ = '1.0.0-beta'

class Gui(tk.Frame):
    """Main program graphical user interface"""
    def __init__(self, master=None, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.validator = InputValidator()
        self.build()

    def build(self):
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
        self.treeview.column("#0", width=120)
        self.treeview.heading("#0", text='input')
        self.treeview.column("A", width=120)
        self.treeview.heading("A", text='osint')
        self.treeview.column("B", width=120)
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
        """validates and sanitizes user input"""
        _input = self.entry.get()
        if _input:
            validated_input = self.validator.validate(_input)
            if validated_input[0]:
                self.status['text'] = validated_input[1]
                self.selector['values'] = validated_input[2]
                self.selector.current(0)
                self.selector.focus()
            else:
                self.status['text'] = "input: invalid"
        elif not _input:
            self.status['text'] = "ready"
            self.selector["values"] = [""]
            self.selector.current(0)

    def run_data_mining(self, event=None):
        """Performs the select OSINT data mining operation"""
        self.status['text'] = "running..."
        _input = self.entry.get()
        transform = self.selector.get()
        try:
            data = self.validator.execute_transform(_input, transform)
            self.treeview.insert('', 'end', text=_input, values=(transform, data))
            # todo: focus on last treeview output to be able to hit enter and iterate
            # item = self.treeview.insert('', 'end', text=_input, values=(transform, data))
            # self.treeview.focus_set()
            # self.treeview.selection_set(item)
            self.entry.focus()
            self.status['text'] = "ready"
        except Exception as e:
            messagebox.showerror("Error", "Error message:" + str(e))

    def selectItem(self, event=None):
        """selects item in treeview and inserts in search box"""
        curItem = self.treeview.focus()
        self.entry.delete(0, 'end')
        self.entry.insert(0, self.treeview.item(curItem)["values"][1])
        self.validate_input()

    @staticmethod
    def quit_program():
        """Quits main program window"""
        root.destroy()

if __name__ == '__main__':
    root = tk.Tk()
    root.title("POCKINT v.{}".format(__version__))
    pockint = Gui(root)
    pockint.pack(expand=False)
    root.iconbitmap('icon.ico')
    root.protocol('WM_DELETE_WINDOW', pockint.quit_program)
    root.mainloop()