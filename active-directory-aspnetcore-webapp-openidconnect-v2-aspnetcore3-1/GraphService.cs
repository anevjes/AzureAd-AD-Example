﻿using Microsoft.Extensions.Configuration;
using Microsoft.Graph;
using Microsoft.Identity.Client;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MoreLinq;
using System.Net.Http.Headers;

namespace WebApp_OpenIDConnect_DotNet
{
    public class GraphService
    {
        private GraphServiceClient _client { get; set; }

        public GraphService(GraphServiceClient graphClient)
        {
            _client = graphClient;
        }
        public async Task<IEnumerable<string>> CheckMemberGroupsAsync(IEnumerable<string> groupIds)
        {
            //You can check up to a maximum of 20 groups per request (see graph api doc).  
            var batchSize = 20;

            var tasks = new List<Task<IDirectoryObjectCheckMemberGroupsCollectionPage>>();
            foreach (var groupsBatch in groupIds.Batch(batchSize))
            {
                tasks.Add(_client.Me.CheckMemberGroups(groupsBatch).Request().PostAsync());
            }
            await Task.WhenAll(tasks);

            return tasks.SelectMany(x => x.Result.ToList());
        }

        public static async Task<GraphService> CreateOnBehalfOfUserAsync(string userToken, IConfiguration configuration)
        {
            var clientApp = ConfidentialClientApplicationBuilder
                .Create(configuration["AzureAD:ClientId"])
                .WithTenantId(configuration["AzureAD:TenantId"])
                .WithClientSecret(configuration["AzureAD:ClientSecret"])
                .Build();

            var authResult = await clientApp
                .AcquireTokenOnBehalfOf(new[] { "User.Read", "GroupMember.Read.All" }, new UserAssertion(userToken))
                .ExecuteAsync();

            GraphServiceClient graphClient = new GraphServiceClient(
                "https://graph.microsoft.com/v1.0",
                new DelegateAuthenticationProvider(async (requestMessage) =>
                {
                    requestMessage.Headers.Authorization = new AuthenticationHeaderValue("bearer", authResult.AccessToken);
                }));

            return new GraphService(graphClient);
        }
    }
}
