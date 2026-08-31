using System;
using System.Threading.Tasks;
using Windows.Security.Credentials;
using Windows.Storage;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;

namespace PronoteLumia
{
    public sealed partial class MainPage : Page
    {
        private const string VaultResource =
            "PronoteLumiaLocalApp";

        private readonly PronoteClient _client =
            new PronoteClient();

        public MainPage()
        {
            InitializeComponent();

            Loaded += MainPage_Loaded;
        }

        private async void MainPage_Loaded(
            object sender,
            RoutedEventArgs e)
        {
            Loaded -= MainPage_Loaded;

            await AutoLoginAsync();
        }

        private async Task AutoLoginAsync()
        {
            try
            {
                var vault =
                    new PasswordVault();

                var credentials =
                    vault.FindAllByResource(
                        VaultResource
                    );

                if (credentials.Count == 0)
                    return;

                var credential =
                    credentials[0];

                credential.RetrievePassword();

                TxtUsername.Text =
                    credential.UserName;

                TxtPassword.Password =
                    credential.Password;

                var settings =
                    ApplicationData.Current
                        .LocalSettings;

                if (settings.Values.ContainsKey(
                    "PronoteUrl"))
                {
                    TxtPronoteUrl.Text =
                        settings.Values[
                            "PronoteUrl"
                        ]?.ToString() ?? "";
                }

                await FetchDataAsync();
            }
            catch (Exception ex)
            {
                TxtStatus.Text =
                    "Erreur : " + ex.Message;
            }
        }

        private async void BtnLogin_Click(
            object sender,
            RoutedEventArgs e)
        {
            try
            {
                var vault =
                    new PasswordVault();

                try
                {
                    var oldCredentials =
                        vault.FindAllByResource(
                            VaultResource
                        );

                    foreach (
                        var credential
                        in oldCredentials)
                    {
                        vault.Remove(
                            credential
                        );
                    }
                }
                catch
                {
                }

                vault.Add(
                    new PasswordCredential(
                        VaultResource,
                        TxtUsername.Text,
                        TxtPassword.Password
                    )
                );

                var settings =
                    ApplicationData.Current
                        .LocalSettings;

                settings.Values[
                    "PronoteUrl"
                ] = TxtPronoteUrl.Text;

                await FetchDataAsync();
            }
            catch (Exception ex)
            {
                TxtStatus.Text =
                    "Erreur : " + ex.Message;
            }
        }

        private async Task FetchDataAsync()
        {
            Loader.IsActive = true;
            TxtStatus.Text = "";

            try
            {
                bool success =
                    await _client.AuthenticateAsync(
                        TxtPronoteUrl.Text,
                        TxtUsername.Text,
                        TxtPassword.Password
                    );

                if (!success)
                {
                    TxtStatus.Text =
                        "Échec de connexion à PRONOTE.";
                    return;
                }

                HomeworkListView.ItemsSource =
                    await _client.GetHomeworkAsync();

                ScheduleListView.ItemsSource =
                    await _client.GetScheduleAsync();

                TxtStatus.Text =
                    "Connexion réussie.";
            }
            catch (Exception ex)
            {
                TxtStatus.Text =
                    "Erreur PRONOTE : " +
                    ex.Message;
            }
            finally
            {
                Loader.IsActive = false;
            }
        }
    }
}