using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.UI;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Server.IISIntegration;
using Microsoft.AspNetCore.Authentication.Negotiate;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.AzureAD.UI;
using Microsoft.AspNetCore.Http;

namespace WebApp_OpenIDConnect_DotNet
{
    public class Startup
    {

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }
        private string _provider { get; set; }


        public void ConfigureServices(IServiceCollection services)
        {

            var authProvider = Configuration.GetSection("Provider").Value;
            if (authProvider.ToLower().Trim().Equals("ad"))
            {
                _provider = "ad";
                //https://docs.microsoft.com/en-us/aspnet/core/security/authentication/windowsauth?view=aspnetcore-5.0&tabs=visual-studio#kestrel
                services.AddAuthentication(NegotiateDefaults.AuthenticationScheme)
   .AddNegotiate();
                services.AddAuthorization(options =>
                {
                    options.AddPolicy("Reader", policy =>
                                      policy.RequireClaim("permission", "reader"));

                    options.AddPolicy("Contributor", policy =>
                                    policy.RequireClaim("permission", "contributor"));
                });

                services.AddControllersWithViews(options =>
                {
                    var policy = new AuthorizationPolicyBuilder()
                        .RequireAuthenticatedUser()
                        .Build();
                    options.Filters.Add(new AuthorizeFilter(policy));
                });
                services.AddRazorPages()
                     .AddMicrosoftIdentityUI();
            }

            else if (authProvider.ToLower().Trim().Equals("azuread"))
            {
                _provider = "azuread";
                services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
                .AddMicrosoftIdentityWebApp(Configuration.GetSection("AzureAd"));

                services.Configure<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme, options =>
                {
                    options.Events = new OpenIdConnectEvents
                    {
                        OnTokenValidated = async ctx =>
                        {
                            var roleGroups = new Dictionary<string, string>();
                            Configuration.Bind("AuthorizationGroups", roleGroups);

                            var graphService = await GraphService.CreateOnBehalfOfUserAsync(ctx.SecurityToken.RawData, Configuration);
                            var memberGroups = await graphService.CheckMemberGroupsAsync(roleGroups.Keys);

                            var claims = memberGroups.Select(groupGuid => new Claim(ClaimTypes.Role, roleGroups[groupGuid]));
                            var appIdentity = new ClaimsIdentity(claims);
                            ctx.Principal.AddIdentity(appIdentity);
                        }
                    };
                });

                services.AddControllersWithViews(options =>
                {
                    var policy = new AuthorizationPolicyBuilder()
                        .RequireAuthenticatedUser()
                        .Build();
                    options.Filters.Add(new AuthorizeFilter(policy));
                });
                services.AddRazorPages()
                     .AddMicrosoftIdentityUI();
            }
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            if (_provider.ToLower().Trim().Equals("azuread"))
            {
                app.UseHttpsRedirection();
                app.UseStaticFiles();

                app.UseRouting();

                app.UseAuthentication();
                app.UseAuthorization();

                app.UseEndpoints(endpoints =>
                {
                    endpoints.MapControllerRoute(
                        name: "default",
                        pattern: "{controller=Home}/{action=Index}/{id?}");
                    endpoints.MapRazorPages();
                });

                app.UseEndpoints(endpoints =>
                {
                    endpoints.MapGet("/", async context =>
                    {
                        await context.Response.WriteAsync("Im authorized (no required role).");
                    }).RequireAuthorization();

                    endpoints.MapGet("/roletest", async context =>
                    {
                        await context.Response.WriteAsync("SUCCESS: You passed the role test!");
                    }).RequireAuthorization(new AuthorizeAttribute() { Roles = "examplerole1" });

                    endpoints.MapGet("/accessdenied", async context =>
                    {
                        await context.Response.WriteAsync("FAIL: Access denied!");
                    });
                });
            }
            else if (_provider.ToLower().Trim().Equals("ad"))
            {
                app.UseHttpsRedirection();
                app.UseStaticFiles();

                app.UseRouting();
                app.UseAuthentication();
                app.UseAuthorization();


                app.UseEndpoints(endpoints =>
                {
                    endpoints.MapControllerRoute(
                        name: "default",
                        pattern: "{controller=Home}/{action=Index}/{id?}");
                });
            }
        }
    }
}
