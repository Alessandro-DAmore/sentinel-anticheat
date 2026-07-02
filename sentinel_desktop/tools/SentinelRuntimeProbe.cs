using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Windows.Forms;

namespace SentinelRuntimeProbe
{
    internal static class Program
    {
        private const string Marker = "--sentinel_runtime_probe";

        [STAThread]
        private static void Main(string[] args)
        {
            if (!args.Any(arg => string.Equals(arg, Marker, StringComparison.OrdinalIgnoreCase)))
            {
                ProcessStartInfo startInfo = new ProcessStartInfo
                {
                    FileName = Application.ExecutablePath,
                    Arguments = Marker,
                    WorkingDirectory = Path.GetDirectoryName(Application.ExecutablePath),
                    UseShellExecute = true
                };
                Process.Start(startInfo);
                return;
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            Form form = new Form
            {
                Text = "Sentinel Runtime Probe",
                StartPosition = FormStartPosition.CenterScreen,
                ClientSize = new Size(520, 250),
                BackColor = Color.FromArgb(4, 9, 15),
                ForeColor = Color.White,
                FormBorderStyle = FormBorderStyle.FixedSingle,
                MaximizeBox = false
            };

            Label title = new Label
            {
                Text = "Sentinel Runtime Probe",
                Font = new Font("Bahnschrift", 20, FontStyle.Bold),
                ForeColor = Color.FromArgb(238, 245, 255),
                Location = new Point(28, 24),
                Size = new Size(460, 40)
            };
            form.Controls.Add(title);

            Label body = new Label
            {
                Text = "Test innocuo attivo. Questo processo non e' un cheat e non modifica il sistema.\r\n\r\nServe solo a verificare che Sentinel rilevi un'anomalia runtime dopo l'accesso in gioco.",
                Font = new Font("Bahnschrift", 10, FontStyle.Regular),
                ForeColor = Color.FromArgb(174, 191, 207),
                Location = new Point(30, 78),
                Size = new Size(455, 86)
            };
            form.Controls.Add(body);

            Label marker = new Label
            {
                Text = "Runtime marker: sentinel_runtime_probe",
                Font = new Font("Consolas", 9, FontStyle.Regular),
                ForeColor = Color.FromArgb(0, 153, 255),
                Location = new Point(30, 170),
                Size = new Size(455, 24)
            };
            form.Controls.Add(marker);

            Button close = new Button
            {
                Text = "Chiudi test",
                Font = new Font("Bahnschrift", 10, FontStyle.Bold),
                Location = new Point(30, 202),
                Size = new Size(130, 32),
                BackColor = Color.FromArgb(0, 102, 178),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            close.FlatAppearance.BorderSize = 0;
            close.Click += (sender, eventArgs) => form.Close();
            form.Controls.Add(close);

            Application.Run(form);
        }
    }
}
