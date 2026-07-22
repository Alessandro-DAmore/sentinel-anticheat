using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Threading;
using System.Windows.Forms;

namespace SentinelDemoMode
{
    internal static class Program
    {
        private const string SignalArgument = "--sentinel_demo_signal";
        private const string BaseRuntimeMarker = "sentinel_demo_cheat_action";

        [STAThread]
        private static void Main(string[] args)
        {
            if (IsSignalMode(args))
            {
                RunSignalProcess(args);
                return;
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new DemoForm());
        }

        private static bool IsSignalMode(string[] args)
        {
            if (args == null)
            {
                return false;
            }

            for (int i = 0; i < args.Length; i++)
            {
                if (string.Equals(args[i], SignalArgument, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private static void RunSignalProcess(string[] args)
        {
            // This process is intentionally harmless. It only stays alive long enough
            // for Sentinel's runtime monitor to read the command line marker.
            DateTime expiresAt = DateTime.UtcNow.AddSeconds(120);
            while (DateTime.UtcNow < expiresAt)
            {
                Thread.Sleep(1000);
            }
        }

        internal static void StartRuntimeSignal(DemoAction action)
        {
            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.FileName = Application.ExecutablePath;
            startInfo.Arguments = string.Format(
                "{0} {1} {2}",
                SignalArgument,
                BaseRuntimeMarker,
                action.Marker
            );
            startInfo.WorkingDirectory = Path.GetDirectoryName(Application.ExecutablePath);
            startInfo.UseShellExecute = false;
            startInfo.CreateNoWindow = true;
            startInfo.WindowStyle = ProcessWindowStyle.Hidden;
            Process.Start(startInfo);
        }
    }

    internal sealed class DemoAction
    {
        public readonly string Title;
        public readonly string Subtitle;
        public readonly string Marker;

        public DemoAction(string title, string subtitle, string marker)
        {
            Title = title;
            Subtitle = subtitle;
            Marker = marker;
        }
    }

    internal sealed class DemoForm : Form
    {
        private readonly Color background = Color.FromArgb(2, 9, 16);
        private readonly Color panel = Color.FromArgb(7, 19, 31);
        private readonly Color border = Color.FromArgb(24, 72, 105);
        private readonly Color blue = Color.FromArgb(0, 153, 255);
        private readonly Color text = Color.FromArgb(235, 244, 255);
        private readonly Color muted = Color.FromArgb(152, 175, 195);
        private readonly Label statusLabel;

        public DemoForm()
        {
            Text = "Sentinel Demo Mode";
            StartPosition = FormStartPosition.CenterScreen;
            ClientSize = new Size(780, 540);
            BackColor = background;
            ForeColor = text;
            FormBorderStyle = FormBorderStyle.FixedSingle;
            MaximizeBox = false;
            Font = new Font("Bahnschrift", 9.5f, FontStyle.Regular);

            BuildHeader();
            BuildActions();

            statusLabel = new Label();
            statusLabel.Text = "Stato: avvio pulito. Sentinel non deve segnalare nulla finche non premi un'azione demo.";
            statusLabel.Font = new Font("Bahnschrift", 10f, FontStyle.Regular);
            statusLabel.ForeColor = Color.FromArgb(255, 208, 98);
            statusLabel.Location = new Point(38, 476);
            statusLabel.Size = new Size(700, 36);
            Controls.Add(statusLabel);
        }

        private void BuildHeader()
        {
            PictureBox logo = new PictureBox();
            logo.Location = new Point(36, 30);
            logo.Size = new Size(140, 140);
            logo.SizeMode = PictureBoxSizeMode.Zoom;
            logo.BackColor = Color.Transparent;
            string logoPath = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "assets", "sentinel-logo.png"));
            if (File.Exists(logoPath))
            {
                logo.Image = Image.FromFile(logoPath);
            }
            Controls.Add(logo);

            Label kicker = new Label();
            kicker.Text = "CONTROLLED OWNER DEMO";
            kicker.Font = new Font("Bahnschrift", 8.5f, FontStyle.Bold);
            kicker.ForeColor = blue;
            kicker.Location = new Point(210, 36);
            kicker.Size = new Size(300, 22);
            Controls.Add(kicker);

            Label title = new Label();
            title.Text = "Sentinel Demo Mode";
            title.Font = new Font("Bahnschrift", 26f, FontStyle.Bold);
            title.ForeColor = text;
            title.Location = new Point(206, 58);
            title.Size = new Size(500, 46);
            Controls.Add(title);

            Label body = new Label();
            body.Text = "Simulatore innocuo per mostrare il rilevamento runtime: l'app parte pulita, poi genera un segnale solo quando premi un'azione.";
            body.Font = new Font("Bahnschrift", 10.5f, FontStyle.Regular);
            body.ForeColor = muted;
            body.Location = new Point(210, 112);
            body.Size = new Size(500, 46);
            Controls.Add(body);

            Label warning = new Label();
            warning.Text = "Non spawna veicoli, non abilita noclip, non inietta moduli e non modifica FiveM.";
            warning.Font = new Font("Bahnschrift", 9.5f, FontStyle.Bold);
            warning.ForeColor = Color.FromArgb(255, 208, 98);
            warning.Location = new Point(210, 160);
            warning.Size = new Size(500, 24);
            Controls.Add(warning);
        }

        private void BuildActions()
        {
            DemoAction[] actions = new DemoAction[]
            {
                new DemoAction("Spawn Sultan", "Simula un comando spawn vehicle", "sentinel_demo_spawn_sultan"),
                new DemoAction("Noclip", "Simula toggle movimento non autorizzato", "sentinel_demo_noclip"),
                new DemoAction("Goto Player", "Simula teletrasporto verso player", "sentinel_demo_goto"),
                new DemoAction("TPM", "Simula teleport to marker", "sentinel_demo_tpm"),
                new DemoAction("Revive", "Simula revive non autorizzato", "sentinel_demo_revive")
            };

            int x = 38;
            int y = 214;
            for (int i = 0; i < actions.Length; i++)
            {
                AddActionCard(actions[i], x, y);
                x += 230;
                if (i == 2)
                {
                    x = 38;
                    y += 122;
                }
            }
        }

        private void AddActionCard(DemoAction action, int x, int y)
        {
            Panel card = new Panel();
            card.Location = new Point(x, y);
            card.Size = new Size(206, 94);
            card.BackColor = panel;
            card.Paint += delegate(object sender, PaintEventArgs e)
            {
                using (Pen pen = new Pen(border, 1))
                {
                    e.Graphics.DrawRectangle(pen, 0, 0, card.Width - 1, card.Height - 1);
                }
            };
            Controls.Add(card);

            Label title = new Label();
            title.Text = action.Title;
            title.Font = new Font("Bahnschrift", 12f, FontStyle.Bold);
            title.ForeColor = text;
            title.Location = new Point(14, 12);
            title.Size = new Size(178, 22);
            card.Controls.Add(title);

            Label subtitle = new Label();
            subtitle.Text = action.Subtitle;
            subtitle.Font = new Font("Bahnschrift", 8.5f, FontStyle.Regular);
            subtitle.ForeColor = muted;
            subtitle.Location = new Point(14, 36);
            subtitle.Size = new Size(178, 22);
            card.Controls.Add(subtitle);

            Button button = new Button();
            button.Text = "Lancia segnale";
            button.Font = new Font("Bahnschrift", 9f, FontStyle.Bold);
            button.Location = new Point(14, 60);
            button.Size = new Size(130, 26);
            button.BackColor = Color.FromArgb(0, 112, 190);
            button.ForeColor = Color.White;
            button.FlatStyle = FlatStyle.Flat;
            button.FlatAppearance.BorderColor = blue;
            button.FlatAppearance.BorderSize = 1;
            button.Click += delegate
            {
                try
                {
                    Program.StartRuntimeSignal(action);
                    statusLabel.Text = "Segnale runtime inviato: " + action.Title + ". Sentinel dovrebbe rilevarlo entro 5-10 secondi mentre sei in game.";
                    statusLabel.ForeColor = Color.FromArgb(255, 208, 98);
                }
                catch (Exception error)
                {
                    statusLabel.Text = "Errore demo: " + error.Message;
                    statusLabel.ForeColor = Color.FromArgb(255, 110, 110);
                }
            };
            card.Controls.Add(button);
        }
    }
}
