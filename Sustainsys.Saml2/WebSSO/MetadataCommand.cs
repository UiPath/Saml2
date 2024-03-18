using Sustainsys.Saml2.Configuration;
using Sustainsys.Saml2.Metadata;
using System;

namespace Sustainsys.Saml2.WebSso
{
    /// <summary>
    /// Represents the service provider metadata command behaviour.
    /// Instances of this class can be created directly or by using the factory method
    /// CommandFactory.GetCommand(CommandFactory.MetadataCommandName).
    /// </summary>
    public class MetadataCommand : ICommand
    {
        /// <summary>
        /// Run the command, creating and returning the service provider metadata.
        /// </summary>
        /// <param name="request">Request data.</param>
        /// <param name="options">Options</param>
        /// <returns>CommandResult</returns>
        public CommandResult Run(HttpRequestData request, IOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            var urls = new Saml2Urls(request, options);

            /* Dynamically fetch the identity provider for the entityid.
             * This will ensure any settings controlled with a feature flag or dynamically refreshed values will be updated after Identity Server startup.
             * We use these identity provider specific settings instead of the startup settings for the rest of the flow.
             * The entityId needs to be organization-specific, so we can't use the entityId from the dynamically loaded options.
             */
            SPOptions spOptions = options.SPOptions;
            EntityId entityId = spOptions.EntityId;
            if (options.IdentityProviders != null && options.IdentityProviders.TryGetValue(entityId, out var identityProvider))
            {
                spOptions = identityProvider.spOptions;
                try
                {
                    spOptions.EntityId = entityId;
                }
                catch (InvalidOperationException ex)
                {
                    // The token handler should not have been instantiated by this point, but just in case, we'll reset to the original SPOptions.
                    spOptions = options.SPOptions;
                    spOptions.Logger?.WriteError("Token handler already instantiated on IdentityProvider. Falling back to original SPOptions.", ex);
                }
            }

			var metadata = spOptions.CreateMetadata(urls);
            options.Notifications.MetadataCreated(metadata, urls);

            var result = new CommandResult()
            {
                Content = metadata.ToXmlString(
					spOptions.SigningServiceCertificate,
                    spOptions.OutboundSigningAlgorithm),
                ContentType = "application/samlmetadata+xml"
            };

            var fileName = CreateFileName(entityId.Id);

            result.Headers.Add("Content-Disposition", "attachment; filename=\"" + fileName + "\"");

            options.Notifications.MetadataCommandResultCreated(result);

            options.SPOptions.Logger.WriteInformation("Created metadata");

            return result;
        }

        private object CreateFileName(string id)
        {
            return id
                .Replace("http://", "")
                .Replace("https://", "")
                .Replace(':', '.')
                .Replace('/', '_')
                + ".xml";
        }
    }
}
