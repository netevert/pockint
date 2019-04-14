import tkinter as tk
import tkinter.ttk as ttk

__version__ = '1.0.0-beta'

class Gui(tk.Frame):
    """Main program graphical user interface"""
    def __init__(self, master=None, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.build()

    def build(self):
        # search frame
        frame_1 = tk.Frame()
        frame_1.pack(expand=False, fill='x', anchor="n")
        
        group = tk.LabelFrame(frame_1, text="input", padx=5, pady=5, fg='brown')
        group.pack(side="top", expand='yes', fill='both', padx=2, pady=2, anchor="n")
        
        f1 = tk.Frame(group)
        f1.pack(expand=True, fill='x', side="top", anchor="n")
        self.entry_main = tk.Entry(f1)
        self.entry_main.pack(expand=True, fill='x', side="top", padx=2, pady=2)
        
        self.selector = ttk.Combobox(f1, values=[""])
        self.selector.pack(expand=True, fill='x', side="top", padx=2, pady=2)
        
        # results frame
        f2 = tk.Frame()
        f2.pack(expand=True, fill='both', anchor="n")
        group_2 = tk.LabelFrame(f2, text="osint", padx=5, pady=5, fg='brown')
        group_2.pack(side="top", expand='yes', fill='both', padx=2, pady=2)
        self.status = tk.Label(f2, text='ready', font=('verdana', 6, 'normal'))
        self.status.pack(anchor='se')
        self.treeview = ttk.Treeview(group_2, column=('A', 'B'),
                                 selectmode='extended', height=5)
        self.treeview.pack(expand=1, fill='both', side=tk.LEFT)
        self.treeview.column("#0", stretch=tk.NO, width=100)
        self.treeview.heading("#0", text='input')
        self.treeview.column("A", width=100, anchor='center')
        self.treeview.heading("A", text='osint')
        self.treeview.column("B", width=100)
        self.treeview.heading("B", text="output")
        self.sbar = tk.Scrollbar(group_2)
        self.treeview.config(yscrollcommand=self.sbar.set)
        self.sbar.config(command=self.treeview.yview)
        self.sbar.pack(expand='no', fill='both', side=tk.LEFT, anchor="e")

    @staticmethod
    def quit_program():
        """Quits main program window"""
        root.destroy()

if __name__ == '__main__':
    root = tk.Tk()
    root.title("POCKINT v.{}".format(__version__))
    pockint = Gui(root)
    # root.config(menu=pockint.top)
    pockint.pack(expand=False)
    # root.resizable(width=False, height=False)
    root.iconbitmap('icon.ico')
    root.protocol('WM_DELETE_WINDOW', pockint.quit_program)
    root.mainloop()