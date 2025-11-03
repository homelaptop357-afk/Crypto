import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime, time as dt_time
import logging

from fetch_data import (
    register_user, authenticate_user, get_all_coins, add_new_coin,
    remove_coin, read_coin_data, add_coin_data, import_csv_to_coin, list_users
)
from visualize import make_analysis_figure

# Matplotlib embed
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
import matplotlib.pyplot as plt

# Optional DateEntry
try:
    from tkcalendar import DateEntry
    HAS_DATEENTRY = True
except Exception:
    HAS_DATEENTRY = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

APP_TITLE = "Crypto Price Tracker (Admin/Client)"


class TimeInput(ttk.Frame):
    def __init__(self, master, initial: dt_time = None, **kw):
        super().__init__(master, **kw)
        if initial is None:
            initial = dt_time(0, 0, 0)
        self.hour = tk.Spinbox(self, from_=0, to=23, width=3, format="%02.0f")
        self.min = tk.Spinbox(self, from_=0, to=59, width=3, format="%02.0f")
        self.sec = tk.Spinbox(self, from_=0, to=59, width=3, format="%02.0f")
        self.hour.grid(row=0, column=0)
        ttk.Label(self, text=":").grid(row=0, column=1)
        self.min.grid(row=0, column=2)
        ttk.Label(self, text=":").grid(row=0, column=3)
        self.sec.grid(row=0, column=4)
        self.set_time(initial)

    def get_time(self):
        try:
            return dt_time(int(self.hour.get()), int(self.min.get()), int(self.sec.get()))
        except Exception:
            return dt_time(0, 0, 0)

    def set_time(self, t: dt_time):
        self.hour.delete(0, tk.END); self.hour.insert(0, f"{t.hour:02d}")
        self.min.delete(0, tk.END); self.min.insert(0, f"{t.minute:02d}")
        self.sec.delete(0, tk.END); self.sec.insert(0, f"{t.second:02d}")


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title(APP_TITLE)
        root.geometry("1000x700")
        self.current_frame = None
        self.show_login()

    def clear_frame(self):
        if self.current_frame:
            self.current_frame.destroy()
            self.current_frame = None

    def show_login(self):
        self.clear_frame()
        frame = ttk.Frame(self.root, padding=16)
        frame.pack(expand=True, fill=tk.BOTH)
        self.current_frame = frame

        ttk.Label(frame, text="Username:").grid(row=0, column=0, sticky=tk.W)
        username_var = tk.StringVar()
        ttk.Entry(frame, textvariable=username_var).grid(row=0, column=1, sticky="ew")

        ttk.Label(frame, text="Password:").grid(row=1, column=0, sticky=tk.W)
        password_var = tk.StringVar()
        ttk.Entry(frame, textvariable=password_var, show="*").grid(row=1, column=1, sticky="ew")

        def do_login():
            u = username_var.get().strip(); p = password_var.get().strip()
            ok, is_admin = authenticate_user(u, p)
            if ok:
                messagebox.showinfo("Login", f"Welcome {u}")
                self.show_main(u, is_admin)
            else:
                messagebox.showerror("Login failed", "Invalid credentials")

        def do_signup():
            u = username_var.get().strip(); p = password_var.get().strip()
            if not u or not p:
                messagebox.showwarning("Signup", "Provide username and password")
                return
            ok, msg = register_user(u, p, is_admin=False)
            if ok:
                messagebox.showinfo("Signup", msg)
            else:
                messagebox.showerror("Signup failed", msg)

        ttk.Button(frame, text="Login", command=do_login).grid(row=2, column=0, pady=12)
        ttk.Button(frame, text="Signup", command=do_signup).grid(row=2, column=1, pady=12)
        frame.columnconfigure(1, weight=1)

    def show_main(self, username: str, is_admin: bool):
        self.clear_frame()
        frame = ttk.Frame(self.root, padding=8)
        frame.pack(expand=True, fill=tk.BOTH)
        self.current_frame = frame
        self.username = username
        self.is_admin = is_admin

        left = ttk.Frame(frame, width=320)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 8))
        right = ttk.Frame(frame)
        right.pack(side=tk.RIGHT, expand=True, fill=tk.BOTH)

        ttk.Label(left, text=f"User: {username} {'(Admin)' if is_admin else ''}").pack(anchor=tk.W)
        ttk.Label(left, text="Select coin:").pack(anchor=tk.W, pady=(8, 0))
        coins = get_all_coins()
        coin_options = [f"{s} - {n}" for s, n in coins]
        coin_var = tk.StringVar()
        coin_cb = ttk.Combobox(left, values=coin_options, textvariable=coin_var, state="readonly", width=28)
        if coin_options:
            coin_cb.current(0)
        coin_cb.pack(anchor=tk.W, pady=4)

        ttk.Button(left, text="Refresh coins", command=lambda: self._refresh_coins(coin_cb)).pack(fill=tk.X, pady=2)

        # Admin-only data-edit controls
        ttk.Label(left, text="(Admin only) Add data to selected coin:").pack(anchor=tk.W, pady=(8, 0))
        if HAS_DATEENTRY:
            date_widget = DateEntry(left, date_pattern="yyyy-MM-dd")
            date_widget.pack(anchor=tk.W)
            get_date = lambda: date_widget.get_date()
        else:
            date_var = tk.StringVar()
            ttk.Entry(left, textvariable=date_var).pack(anchor=tk.W)
            ttk.Label(left, text="(YYYY-MM-DD)").pack(anchor=tk.W)
            def get_date():
                try:
                    return datetime.strptime(date_var.get().strip(), "%Y-%m-%d").date()
                except Exception:
                    return None

        ttk.Label(left, text="Time (HH:MM:SS):").pack(anchor=tk.W, pady=(6, 0))
        time_input = TimeInput(left)
        time_input.pack(anchor=tk.W, pady=(0, 6))

        ttk.Label(left, text="Price:").pack(anchor=tk.W)
        price_var = tk.StringVar()
        ttk.Entry(left, textvariable=price_var).pack(fill=tk.X)

        # Buttons: if admin show add/import; if client hide/disable them
        btn_add_data = ttk.Button(left, text="Add data row (admin)", command=lambda: self._add_coin_row(coin_var, get_date, time_input, price_var))
        btn_import = ttk.Button(left, text="Import CSV to coin (admin)", command=lambda: self._import_csv_to_coin(coin_var))
        if self.is_admin:
            btn_add_data.pack(fill=tk.X, pady=(6, 2))
            btn_import.pack(fill=tk.X, pady=(2, 8))
        else:
            ttk.Label(left, text="(Data editing is admin-only)").pack(anchor=tk.W, pady=(6, 8))

        ttk.Button(left, text="Analyze & Plot", command=lambda: self._analyze_and_plot(coin_var, right)).pack(fill=tk.X, pady=2)

        ttk.Label(left, text="Forecast days:").pack(anchor=tk.W, pady=(8, 0))
        predict_var = tk.IntVar(value=30)
        ttk.Spinbox(left, from_=1, to=365, textvariable=predict_var, width=8).pack(anchor=tk.W)
        log_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(left, text="Log scale", variable=log_var).pack(anchor=tk.W, pady=(6, 0))

        # Admin: manage coins and users
        if self.is_admin:
            ttk.Separator(left, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=8)
            ttk.Label(left, text="Admin: add/remove coins").pack(anchor=tk.W)
            new_sym = tk.StringVar(); new_name = tk.StringVar()
            ttk.Entry(left, textvariable=new_sym).pack(anchor=tk.W, pady=(4, 0))
            ttk.Entry(left, textvariable=new_name).pack(anchor=tk.W, pady=(2, 4))
            ttk.Button(left, text="Add coin", command=lambda: self._add_coin(new_sym, new_name, coin_cb)).pack(fill=tk.X)
            rem_sym = tk.StringVar()
            ttk.Entry(left, textvariable=rem_sym).pack(fill=tk.X, pady=(6, 0))
            ttk.Button(left, text="Remove coin", command=lambda: self._remove_coin(rem_sym, coin_cb)).pack(fill=tk.X, pady=(2, 4))
            ttk.Button(left, text="Refresh users list", command=self._refresh_users).pack(fill=tk.X, pady=(6, 2))
            self.users_list = tk.Listbox(left, height=6)
            self.users_list.pack(fill=tk.X, pady=(4, 0))
            self._refresh_users()

        # Right: canvas area
        self.canvas_frame = ttk.Frame(right)
        self.canvas_frame.pack(expand=True, fill=tk.BOTH)
        self._current_canvas = None
        self._current_toolbar = None

        self.status_var = tk.StringVar(value="")
        ttk.Label(self.root, textvariable=self.status_var).pack(side=tk.BOTTOM, fill=tk.X)

        # store some refs
        self._coin_cb = coin_cb
        self._predict_var = predict_var
        self._log_var = log_var
        self._is_admin = self.is_admin

    def _refresh_coins(self, coin_cb):
        coins = get_all_coins()
        coin_cb["values"] = [f"{s} - {n}" for s, n in coins]
        if coin_cb["values"]:
            coin_cb.current(0)
        self._set_status("Coins refreshed")

    def _refresh_users(self):
        try:
            users = list_users()
            self.users_list.delete(0, tk.END)
            for u in users:
                self.users_list.insert(tk.END, u)
            self._set_status("Users refreshed")
        except Exception as e:
            self._set_status(f"Users refresh error: {e}")

    def _parse_selected_coin(self, val: str):
        if not val:
            return None
        if "-" in val:
            return val.split("-", 1)[0].strip()
        return val.strip()

    # Admin actions
    def _add_coin_row(self, coin_var, get_date_func, time_input, price_var):
        if not self._is_admin:
            messagebox.showerror("Permission", "Only admins can add data.")
            return
        symbol = self._parse_selected_coin(coin_var.get())
        if not symbol:
            messagebox.showwarning("Add data", "Select a coin.")
            return
        date_obj = get_date_func()
        if date_obj is None:
            messagebox.showerror("Add data", "Invalid date.")
            return
        t = time_input.get_time()
        dt = datetime.combine(date_obj, t)
        dtstr = dt.strftime("%Y-%m-%d %H:%M:%S")
        try:
            price = float(price_var.get().strip())
        except Exception:
            messagebox.showerror("Add data", "Invalid price.")
            return
        ok, msg = add_coin_data(symbol, dtstr, price)
        if ok:
            messagebox.showinfo("Add data", msg)
            price_var.set("")
        else:
            messagebox.showerror("Add data", msg)
        self._set_status(msg)

    def _import_csv_to_coin(self, coin_var):
        if not self._is_admin:
            messagebox.showerror("Permission", "Only admins can import data.")
            return
        symbol = self._parse_selected_coin(coin_var.get())
        if not symbol:
            messagebox.showwarning("Import", "Select a coin.")
            return
        path = filedialog.askopenfilename(title="Select CSV", filetypes=[("CSV","*.csv"),("All files","*.*")])
        if not path:
            return
        ok, msg = import_csv_to_coin(symbol, path)
        if ok:
            messagebox.showinfo("Import", msg)
        else:
            messagebox.showerror("Import", msg)
        self._set_status(msg)

    def _add_coin(self, sym_var, name_var, coin_cb):
        if not self._is_admin:
            messagebox.showerror("Permission", "Only admins can manage coins.")
            return
        sym = sym_var.get().strip(); name = name_var.get().strip()
        if not sym or not name:
            messagebox.showwarning("Admin", "Provide symbol and name")
            return
        ok, msg = add_new_coin(sym, name)
        if ok:
            messagebox.showinfo("Admin", msg)
            sym_var.set(""); name_var.set("")
            self._refresh_coins(coin_cb)
        else:
            messagebox.showerror("Admin", msg)

    def _remove_coin(self, rem_var, coin_cb):
        if not self._is_admin:
            messagebox.showerror("Permission", "Only admins can manage coins.")
            return
        sym = rem_var.get().strip()
        if not sym:
            messagebox.showwarning("Admin", "Provide symbol to remove")
            return
        ok, msg = remove_coin(sym)
        if ok:
            messagebox.showinfo("Admin", msg)
            rem_var.set("")
            self._refresh_coins(coin_cb)
        else:
            messagebox.showerror("Admin", msg)

    # Analysis / plotting (allowed for clients and admins)
    def _analyze_and_plot(self, coin_var, right_frame):
        symbol = self._parse_selected_coin(coin_var.get())
        if not symbol:
            messagebox.showwarning("Analyze", "Select a coin.")
            return
        df = read_coin_data(symbol)
        if df.empty or len(df) < 1:
            messagebox.showinfo("Analyze", "No data available for this coin.")
            return
        predict_days = int(self._predict_var.get())
        log_scale = bool(self._log_var.get())
        try:
            fig = make_analysis_figure(df, predict_days=predict_days, ma_windows=(7, 30), show_trend=True, log_scale=log_scale)
        except Exception as e:
            messagebox.showerror("Analyze error", str(e))
            return

        # clear previous canvas
        if self._current_canvas:
            try:
                self._current_canvas.get_tk_widget().destroy()
            except Exception:
                pass
            self._current_canvas = None
        if self._current_toolbar:
            try:
                self._current_toolbar.destroy()
            except Exception:
                pass
            self._current_toolbar = None

        canvas = FigureCanvasTkAgg(fig, master=self.canvas_frame)
        canvas.draw()
        widget = canvas.get_tk_widget()
        widget.pack(fill=tk.BOTH, expand=True)
        toolbar = NavigationToolbar2Tk(canvas, self.canvas_frame)
        toolbar.update()
        toolbar.pack()
        self._current_canvas = canvas
        self._current_toolbar = toolbar
        self._set_status(f"Plotted {symbol}")

    def _set_status(self, msg: str):
        if hasattr(self, "status_var"):
            self.status_var.set(msg)


def main():
    root = tk.Tk()
    app = App(root)
    root.mainloop()


if __name__ == "__main__":
    main()