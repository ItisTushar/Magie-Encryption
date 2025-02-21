import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading

# Import your encode/decode functions from your existing modules
from encode import encode
from decode import decode

class ChessEncryptionGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Chess Encryption System")
        self.geometry("600x500")
        
        # To store intermediate results
        self.encode_file_path = ""
        self.encoded_pgn = ""
        self.decode_pgn_file_path = ""
        
        # Create a Notebook with two tabs
        notebook = ttk.Notebook(self)
        notebook.pack(expand=True, fill='both')
        
        # ---------------------
        # Encode Tab
        # ---------------------
        encode_frame = ttk.Frame(notebook)
        notebook.add(encode_frame, text="Encode")
        
        # Button to select file to encode
        ttk.Button(encode_frame, text="Select File to Encode",
                   command=self.select_encode_file).pack(pady=10)
        
        # Label to display selected file or status
        self.encode_status_var = tk.StringVar(value="No file selected.")
        ttk.Label(encode_frame, textvariable=self.encode_status_var).pack(pady=5)
        
        # Button to start encoding in a separate thread
        ttk.Button(encode_frame, text="Encode File",
                   command=self.run_encode_thread).pack(pady=10)
        
        # Text widget to preview PGN result (optional)
        self.encode_text = tk.Text(encode_frame, height=10)
        self.encode_text.pack(expand=True, fill='both', padx=10, pady=10)
        
        # Button to save PGN output using file dialog
        ttk.Button(encode_frame, text="Save PGN",
                   command=self.save_pgn).pack(pady=10)
        
        # ---------------------
        # Decode Tab
        # ---------------------
        decode_frame = ttk.Frame(notebook)
        notebook.add(decode_frame, text="Decode")
        
        # Button to select PGN file to decode
        ttk.Button(decode_frame, text="Select PGN File to Decode",
                   command=self.select_decode_file).pack(pady=10)
        
        # Label to show selected PGN file and status
        self.decode_status_var = tk.StringVar(value="No PGN file selected.")
        ttk.Label(decode_frame, textvariable=self.decode_status_var).pack(pady=5)
        
        # Button to decode the selected PGN file
        ttk.Button(decode_frame, text="Decode PGN",
                   command=self.run_decode_thread).pack(pady=10)
        
        # Label to show where the decoded file was saved
        self.decode_output_label = ttk.Label(decode_frame, text="Decoded file saved: N/A")
        self.decode_output_label.pack(pady=10)
    
    # ---------------------
    # Encode Tab Functions
    # ---------------------
    def select_encode_file(self):
        file_path = filedialog.askopenfilename(title="Select File to Encode")
        if file_path:
            self.encode_file_path = file_path
            self.encode_status_var.set(f"Selected: {file_path}")
        else:
            self.encode_status_var.set("No file selected.")
    
    def run_encode_thread(self):
        if not self.encode_file_path:
            messagebox.showerror("Error", "Please select a file to encode.")
            return
        self.encode_status_var.set("Encoding in progress...")
        threading.Thread(target=self.run_encode).start()
    
    def run_encode(self):
        try:
            pgn_output = encode(self.encode_file_path)
            self.encoded_pgn = pgn_output
            # Preview part of the PGN output
            self.encode_text.delete(1.0, tk.END)
            self.encode_text.insert(tk.END, pgn_output[:1000])
            self.encode_status_var.set("Encoding completed.")
        except Exception as e:
            self.encode_status_var.set("Error during encoding.")
            messagebox.showerror("Encoding Error", str(e))
    
    def save_pgn(self):
        if not self.encoded_pgn:
            messagebox.showerror("Error", "No PGN data available. Please encode a file first.")
            return
        file_path = filedialog.asksaveasfilename(
            title="Save PGN File",
            defaultextension=".pgn",
            filetypes=[("PGN Files", "*.pgn")]
        )
        if file_path:
            try:
                with open(file_path, "w") as f:
                    f.write(self.encoded_pgn)
                messagebox.showinfo("Success", f"PGN saved to: {file_path}")
                # Reset encode tab after saving
                self.reset_encode_tab()
            except Exception as e:
                messagebox.showerror("Save Error", str(e))
    
    def reset_encode_tab(self):
        # Reset encode-related variables and UI elements
        self.encode_file_path = ""
        self.encoded_pgn = ""
        self.encode_status_var.set("No file selected.")
        self.encode_text.delete(1.0, tk.END)
    
    # ---------------------
    # Decode Tab Functions
    # ---------------------
    def select_decode_file(self):
        file_path = filedialog.askopenfilename(
            title="Select PGN File to Decode",
            filetypes=[("PGN Files", "*.pgn")]
        )
        if file_path:
            self.decode_pgn_file_path = file_path
            self.decode_status_var.set(f"Selected: {file_path}")
        else:
            self.decode_status_var.set("No PGN file selected.")
    
    def run_decode_thread(self):
        if not self.decode_pgn_file_path:
            messagebox.showerror("Error", "Please select a PGN file to decode.")
            return
        # Ask user for output file base path (the decode function will append the correct extension)
        output_file_path = filedialog.asksaveasfilename(
            title="Save Decoded File As",
            defaultextension="",
            filetypes=[("All Files", "*.*")]
        )
        if not output_file_path:
            return
        self.decode_status_var.set("Decoding in progress...")
        threading.Thread(target=self.run_decode, args=(self.decode_pgn_file_path, output_file_path)).start()
    
    def run_decode(self, pgn_file_path, output_file_path):
        try:
            with open(pgn_file_path, "r") as f:
                pgn_input = f.read()
            decode(pgn_input, output_file_path)
            messagebox.showinfo("Success", f"Decoded file saved as: {output_file_path}")
            self.decode_status_var.set("Decoding completed.")
            # Reset decode tab after successful decode
            self.reset_decode_tab()
        except Exception as e:
            self.decode_status_var.set("Error during decoding.")
            messagebox.showerror("Decoding Error", str(e))
    
    def reset_decode_tab(self):
        # Reset decode-related variables and UI elements
        self.decode_pgn_file_path = ""
        self.decode_status_var.set("No PGN file selected.")
        self.decode_output_label.config(text="Decoded file saved: N/A")

