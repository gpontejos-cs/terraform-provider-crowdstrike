package cloudsecurity

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                   = &cloudSecuritySuppressionRuleResource{}
	_ resource.ResourceWithConfigure      = &cloudSecuritySuppressionRuleResource{}
	_ resource.ResourceWithImportState    = &cloudSecuritySuppressionRuleResource{}
	_ resource.ResourceWithValidateConfig = &cloudSecuritySuppressionRuleResource{}
)

func NewCloudSecuritySuppressionRuleResource() resource.Resource {
	return &cloudSecuritySuppressionRuleResource{}
}

type cloudSecuritySuppressionRuleResource struct {
	client *client.CrowdStrikeAPISpecification
}

// Main resource model
type cloudSecuritySuppressionRuleResourceModel struct {
	ID                        types.String              `tfsdk:"id"`
	Description               types.String              `tfsdk:"description"`
	Domain                    types.String              `tfsdk:"domain"`
	Name                      types.String              `tfsdk:"name"`
	RuleSelectionFilter       *ruleSelectionFilterModel `tfsdk:"rule_selection_filter"`
	RuleSelectionType         types.String              `tfsdk:"rule_selection_type"`
	ScopeAssetFilter          *scopeAssetFilterModel    `tfsdk:"scope_asset_filter"`
	ScopeType                 types.String              `tfsdk:"scope_type"`
	Subdomain                 types.String              `tfsdk:"subdomain"`
	SuppressionComment        types.String              `tfsdk:"suppression_comment"`
	SuppressionExpirationDate types.String              `tfsdk:"suppression_expiration_date"`
	SuppressionReason         types.String              `tfsdk:"suppression_reason"`
}

// Rule selection filter model
type ruleSelectionFilterModel struct {
	RuleIds        types.Set `tfsdk:"rule_ids"`
	RuleNames      types.Set `tfsdk:"rule_names"`
	RuleOrigins    types.Set `tfsdk:"rule_origins"`
	RuleProviders  types.Set `tfsdk:"rule_providers"`
	RuleServices   types.Set `tfsdk:"rule_services"`
	RuleSeverities types.Set `tfsdk:"rule_severities"`
}

// Scope asset filter model
type scopeAssetFilterModel struct {
	AccountIds        types.Set `tfsdk:"account_ids"`
	CloudGroupIds     types.Set `tfsdk:"cloud_group_ids"`
	CloudProviders    types.Set `tfsdk:"cloud_providers"`
	Regions           types.Set `tfsdk:"regions"`
	ResourceIds       types.Set `tfsdk:"resource_ids"`
	ResourceNames     types.Set `tfsdk:"resource_names"`
	ResourceTypes     types.Set `tfsdk:"resource_types"`
	ServiceCategories types.Set `tfsdk:"service_categories"`
	Tags              types.Set `tfsdk:"tags"`
}

func (m *cloudSecuritySuppressionRuleResourceModel) wrap(
	_ context.Context,
	rule models.ApimodelsSuppressionRule,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = types.StringValue(*rule.ID)
	m.Description = types.StringValue(rule.Description)
	m.Domain = types.StringPointerValue(rule.Domain)
	m.Name = types.StringPointerValue(rule.Name)
	m.RuleSelectionType = types.StringPointerValue(rule.RuleSelectionType)
	m.ScopeType = types.StringPointerValue(rule.ScopeType)
	m.Subdomain = types.StringPointerValue(rule.Subdomain)
	m.SuppressionComment = types.StringValue(rule.SuppressionComment)
	m.SuppressionExpirationDate = types.StringValue(rule.SuppressionExpirationDate)
	m.SuppressionReason = types.StringPointerValue(rule.SuppressionReason)

	var convertedRuleSeverities []string
	for _, severity := range rule.RuleSelectionFilter.RuleSeverities {
		convertedRuleSeverities = append(convertedRuleSeverities, stringToSeverity[severity])
	}

	if rule.RuleSelectionFilter != nil {
		m.RuleSelectionFilter = &ruleSelectionFilterModel{
			RuleIds:        types.SetValueMust(types.StringType, convertSliceToSet(rule.RuleSelectionFilter.RuleIds)),
			RuleNames:      types.SetValueMust(types.StringType, convertSliceToSet(rule.RuleSelectionFilter.RuleNames)),
			RuleOrigins:    types.SetValueMust(types.StringType, convertSliceToSet(rule.RuleSelectionFilter.RuleOrigins)),
			RuleProviders:  types.SetValueMust(types.StringType, convertSliceToSet(rule.RuleSelectionFilter.RuleProviders)),
			RuleServices:   types.SetValueMust(types.StringType, convertSliceToSet(rule.RuleSelectionFilter.RuleServices)),
			RuleSeverities: types.SetValueMust(types.StringType, convertSliceToSet(convertedRuleSeverities)),
		}
	}

	var cloudGroupIds []string = []string{}
	if rule.ScopeAssetFilter != nil && len(rule.ScopeAssetFilter.CloudGroups) != 0 {
		for _, cloudGroup := range rule.ScopeAssetFilter.CloudGroups {
			cloudGroupIds = append(cloudGroupIds, *cloudGroup.ID)
		}
	}

	if rule.ScopeAssetFilter != nil {
		m.ScopeAssetFilter = &scopeAssetFilterModel{
			AccountIds:        types.SetValueMust(types.StringType, convertSliceToSet(rule.ScopeAssetFilter.AccountIds)),
			CloudGroupIds:     types.SetValueMust(types.StringType, convertSliceToSet(cloudGroupIds)),
			CloudProviders:    types.SetValueMust(types.StringType, convertSliceToSet(rule.ScopeAssetFilter.CloudProviders)),
			Regions:           types.SetValueMust(types.StringType, convertSliceToSet(rule.ScopeAssetFilter.Regions)),
			ResourceIds:       types.SetValueMust(types.StringType, convertSliceToSet(rule.ScopeAssetFilter.ResourceIds)),
			ResourceNames:     types.SetValueMust(types.StringType, convertSliceToSet(rule.ScopeAssetFilter.ResourceNames)),
			ResourceTypes:     types.SetValueMust(types.StringType, convertSliceToSet(rule.ScopeAssetFilter.ResourceTypes)),
			ServiceCategories: types.SetValueMust(types.StringType, convertSliceToSet(rule.ScopeAssetFilter.ServiceCategories)),
			Tags:              types.SetValueMust(types.StringType, convertSliceToSet(rule.ScopeAssetFilter.Tags)),
		}
	}

	return diags
}

func (r *cloudSecuritySuppressionRuleResource) Configure(
	ctx context.Context,
	req resource.ConfigureRequest,
	resp *resource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*client.CrowdStrikeAPISpecification)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf(
				"Expected *client.CrowdStrikeAPISpecification, got: %T. Please report this issue to the provider developers.",
				req.ProviderData,
			),
		)

		return
	}

	r.client = client
}

func (r *cloudSecuritySuppressionRuleResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_security_suppression_rule"
}

func (r *cloudSecuritySuppressionRuleResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		Description: "Description of your resource",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Unique identifier of the suppression rule.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`),
						"must be a valid Id in the format of 7c86a274-c04b-4292-9f03-dafae42bde97",
					),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
					stringplanmodifier.RequiresReplace(),
				},
			},
			"description": schema.StringAttribute{
				Description: "Description of the suppression rule",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(""),
			},
			"domain": schema.StringAttribute{
				Description: "Defines the Rule domain to which this suppression rule applies. Updating requires replacement.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"name": schema.StringAttribute{
				Description: "Name of the suppression rule",
				Required:    true,
			},
			"rule_selection_type": schema.StringAttribute{
				Description: "One of: all_rules, rule_selection_filter",
				Required:    true,
				Validators: []validator.String{
					stringvalidator.OneOf(
						"all_rules",
						"rule_selection_filter",
					),
				},
			},
			"scope_type": schema.StringAttribute{
				Description: "Type of scope",
				Required:    true,
				Validators: []validator.String{
					stringvalidator.OneOf(
						"all_assets",
						"asset_filter",
					),
				},
			},
			"subdomain": schema.StringAttribute{
				Description: "Specifies the rule subdomain to which this suppression rule applies. Updating requires replacement.",
				Required:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"suppression_comment": schema.StringAttribute{
				Description: "Comment for suppression",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(""),
			},
			"suppression_expiration_date": schema.StringAttribute{
				Description: "Expiration date for suppression. If defined, must be in RFC3339 format (e.g., '2025-08-11T10:00:00Z').",
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(""),
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)?$`),
						"must be in RFC3339 format (e.g., '2025-08-11T10:00:00Z') if defined",
					),
				},
			},
			"suppression_reason": schema.StringAttribute{
				Description: "Reason for suppression",
				Required:    true,
			},
		},
		Blocks: map[string]schema.Block{
			"rule_selection_filter": schema.SingleNestedBlock{
				Description: "Filter criteria for rule selection",
				Attributes: map[string]schema.Attribute{
					"rule_ids": schema.SetAttribute{
						Description: "Set of rule IDs",
						ElementType: types.StringType,
						Optional:    true,
						Computed:    true,
						Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})),
					},
					"rule_names": schema.SetAttribute{
						Description: "Set of rule names",
						ElementType: types.StringType,
						Optional:    true,
						Computed:    true,
						Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})),
					},
					"rule_origins": schema.SetAttribute{
						Description: "Set of rule origins",
						ElementType: types.StringType,
						Optional:    true,
						Computed:    true,
						Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})),
					},
					"rule_providers": schema.SetAttribute{
						Description: "Set of rule providers",
						ElementType: types.StringType,
						Optional:    true,
						Computed:    true,
						Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})),
					},
					"rule_services": schema.SetAttribute{
						Description: "Set of rule services",
						ElementType: types.StringType,
						Optional:    true,
						Computed:    true,
						Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})),
					},
					"rule_severities": schema.SetAttribute{
						Description: "Set of rule severities",
						ElementType: types.StringType,
						Optional:    true,
						Computed:    true,
						Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})),
						Validators: []validator.Set{
							setvalidator.ValueStringsAre(
								stringvalidator.OneOf("critical", "high", "medium", "informational"),
							),
						},
					},
				},
			},
			"scope_asset_filter": schema.SingleNestedBlock{
				Description: "Filter criteria for scope assets",
				Attributes: map[string]schema.Attribute{
					"account_ids": schema.SetAttribute{
						Description: "Set of account IDs",
						ElementType: types.StringType,
						Optional:    true,
						Computed:    true,
						Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})),
					},
					"cloud_group_ids": schema.SetAttribute{
						Description: "Set of cloud group IDs",
						ElementType: types.StringType,
						Optional:    true,
						Computed:    true,
						Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})),
					},
					"cloud_providers": schema.SetAttribute{
						Description: "Set of cloud providers",
						ElementType: types.StringType,
						Optional:    true,
						Computed:    true,
						Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})),
					},
					"regions": schema.SetAttribute{
						Description: "Set of regions",
						ElementType: types.StringType,
						Optional:    true,
						Computed:    true,
						Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})),
					},
					"resource_ids": schema.SetAttribute{
						Description: "Set of resource IDs",
						ElementType: types.StringType,
						Optional:    true,
						Computed:    true,
						Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})),
					},
					"resource_names": schema.SetAttribute{
						Description: "Set of resource names",
						ElementType: types.StringType,
						Optional:    true,
						Computed:    true,
						Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})),
					},
					"resource_types": schema.SetAttribute{
						Description: "Set of resource types",
						ElementType: types.StringType,
						Optional:    true,
						Computed:    true,
						Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})),
					},
					"service_categories": schema.SetAttribute{
						Description: "Set of service categories",
						ElementType: types.StringType,
						Optional:    true,
						Computed:    true,
						Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})),
					},
					"tags": schema.SetAttribute{
						Description: "Set of tags",
						ElementType: types.StringType,
						Optional:    true,
						Computed:    true,
						Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})),
					},
				},
			},
		},
	}
}

func (r *cloudSecuritySuppressionRuleResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config cloudSecuritySuppressionRuleResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Validate rule_selection_type and rule_selection_filter
	if config.RuleSelectionType.ValueString() == "rule_selection_filter" && config.RuleSelectionFilter == nil {
		resp.Diagnostics.AddAttributeError(
			path.Root("rule_selection_filter"),
			"Missing Rule Selection Filter",
			"When rule_selection_type is set to 'rule_selection_filter', rule_selection_filter must be provided.",
		)
	}

	// Validate scope_type and scope_asset_filter
	if config.ScopeType.ValueString() == "asset_filter" && config.ScopeAssetFilter == nil {
		resp.Diagnostics.AddAttributeError(
			path.Root("scope_asset_filter"),
			"Missing Scope Asset Filter",
			"When scope_type is set to 'asset_filter', scope_asset_filter must be provided.",
		)
	}

	// Validate suppression_expiration_date format
	if !config.SuppressionExpirationDate.IsNull() && config.SuppressionExpirationDate.ValueString() != "" {
		_, err := time.Parse(time.RFC3339, config.SuppressionExpirationDate.ValueString())
		if err != nil {
			resp.Diagnostics.AddAttributeError(
				path.Root("suppression_expiration_date"),
				"Invalid Date Format",
				"The suppression_expiration_date must be in RFC3339 format (e.g., '2006-01-02T15:04:05Z').",
			)
		}
	}

	// Validate that all_assets and all_rules are not used together
	if config.RuleSelectionType.ValueString() == "all_rules" && config.ScopeType.ValueString() == "all_assets" {
		resp.Diagnostics.AddError(
			"Invalid Configuration",
			"The combination of 'all_rules' for rule_selection_type and 'all_assets' for scope_type is not supported.",
		)
	}

}

func (r *cloudSecuritySuppressionRuleResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan cloudSecuritySuppressionRuleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	rule, diags := r.createSuppressionRule(ctx, plan)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, *rule)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *cloudSecuritySuppressionRuleResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state cloudSecuritySuppressionRuleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	rule, diags := r.getSuppressionRule(ctx, state.ID.ValueString())
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.Diagnostics.Append(state.wrap(ctx, *rule)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *cloudSecuritySuppressionRuleResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan cloudSecuritySuppressionRuleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	rule, diags := r.updateSuppressionRule(ctx, plan)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.Diagnostics.Append(plan.wrap(ctx, *rule)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *cloudSecuritySuppressionRuleResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state cloudSecuritySuppressionRuleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.deleteSuppressionRule(ctx, state.ID.ValueString())...)
}

func (r *cloudSecuritySuppressionRuleResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *cloudSecuritySuppressionRuleResource) getSuppressionRule(ctx context.Context, id string) (*models.ApimodelsSuppressionRule, diag.Diagnostics) {
	var diags diag.Diagnostics

	params := cloud_policies.GetSuppressionRulesParams{
		Context: ctx,
		Ids:     []string{id},
	}

	resp, err := r.client.CloudPolicies.GetSuppressionRules(&params)
	if err != nil {
		if badRequest, ok := err.(*cloud_policies.GetSuppressionRulesBadRequest); ok {
			diags.AddError(
				"Error Retrieving Suppression Rule",
				fmt.Sprintf("Failed to retrieve suppression rule (400): %s, %+v", id, *badRequest.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		if internalServerError, ok := err.(*cloud_policies.GetSuppressionRulesInternalServerError); ok {
			diags.AddError(
				"Error Retrieving Suppression Rule",
				fmt.Sprintf("Failed to retrieve suppression rule (500): %s, %+v", id, *internalServerError.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		diags.AddError(
			"Error Retrieving Suppression Rule",
			fmt.Sprintf("Failed to retrieve rule %s: %+v", id, err),
		)

		return nil, diags
	}

	if resp == nil || resp.Payload == nil || len(resp.Payload.Resources) == 0 {
		diags.AddError(
			"Error Retrieving Suppression Rule",
			fmt.Sprintf("Failed to retrieve suppression rule %s: API returned an empty response", id),
		)
		return nil, diags
	}

	payload := resp.GetPayload()

	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.AddError(
			"Error Updating Rule",
			fmt.Sprintf("Failed to update rule: %s", err.Error()),
		)
		return nil, diags
	}

	return payload.Resources[0], nil
}

func convertSliceToSet(slice []string) []attr.Value {
	set := make([]attr.Value, len(slice))
	for i, v := range slice {
		set[i] = types.StringValue(v)
	}
	return set
}

func (r *cloudSecuritySuppressionRuleResource) createSuppressionRule(ctx context.Context, rule cloudSecuritySuppressionRuleResourceModel) (*models.ApimodelsSuppressionRule, diag.Diagnostics) {
	var diags diag.Diagnostics

	// Required Params
	body := &models.SuppressionrulesCreateSuppressionRuleRequest{
		Name:              rule.Name.ValueStringPointer(),
		Domain:            rule.Domain.ValueStringPointer(),
		RuleSelectionType: rule.RuleSelectionType.ValueStringPointer(),
		ScopeType:         rule.ScopeType.ValueStringPointer(),
		Subdomain:         rule.Subdomain.ValueStringPointer(),
		SuppressionReason: rule.SuppressionReason.ValueStringPointer(),
	}

	// Optional Params
	// Maybe add these to the body initially instead.
	if !rule.Description.IsNull() {
		body.Description = rule.Description.ValueString()
	}

	if !rule.SuppressionComment.IsNull() {
		body.SuppressionComment = rule.SuppressionComment.ValueString()
	}

	if !rule.SuppressionExpirationDate.IsNull() {
		body.SuppressionExpirationDate = rule.SuppressionExpirationDate.ValueString()
	}

	if rule.RuleSelectionType.ValueString() == "rule_selection_filter" {
		ruleSelectionFilter, diags := createSuppressionRuleSelectionFilter(ctx, *rule.RuleSelectionFilter)
		if diags.HasError() {
			return nil, diags
		}

		body.RuleSelectionFilter = ruleSelectionFilter
	}

	if rule.ScopeType.ValueString() == "asset_filter" {
		scopeAssetFilter, diags := createSuppressionrulesScopeAssetFilter(ctx, *rule.ScopeAssetFilter)
		if diags.HasError() {
			return nil, diags
		}

		body.ScopeAssetFilter = scopeAssetFilter
	}

	params := cloud_policies.CreateSuppressionRuleParams{
		Context: ctx,
		Body:    body,
	}

	resp, err := r.client.CloudPolicies.CreateSuppressionRule(&params)
	if err != nil {
		if badRequest, ok := err.(*cloud_policies.CreateSuppressionRuleBadRequest); ok {
			diags.AddError(
				"Error Creating Suppression Rule",
				fmt.Sprintf("Failed to create suppression rule (400): %s, %+v", rule.Name.ValueString(), *badRequest.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		if internalServerError, ok := err.(*cloud_policies.CreateSuppressionRuleInternalServerError); ok {
			diags.AddError(
				"Error Creating Suppression Rule",
				fmt.Sprintf("Failed to create suppression rule (500): %s, %+v", rule.Name.ValueString(), *internalServerError.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		diags.AddError(
			"Error Creating Suppression Rule",
			fmt.Sprintf("Failed to create suppression rule %s: %+v", rule.Name.ValueString(), err),
		)

		return nil, diags
	}

	if resp == nil || resp.Payload == nil || len(resp.Payload.Resources) == 0 {
		diags.AddError(
			"Error Creating Suppression Rule",
			fmt.Sprintf("Failed to create suppression rule %s: API returned an empty response", rule.Name.ValueString()),
		)
		return nil, diags
	}

	payload := resp.GetPayload()

	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.AddError(
			"Error Creating Suppression Rule",
			fmt.Sprintf("Failed to create suppression rule: %s", err.Error()),
		)
		return nil, diags
	}

	return r.getSuppressionRule(ctx, payload.Resources[0])
}

func (r *cloudSecuritySuppressionRuleResource) updateSuppressionRule(ctx context.Context, rule cloudSecuritySuppressionRuleResourceModel) (*models.ApimodelsSuppressionRule, diag.Diagnostics) {
	var diags diag.Diagnostics

	body := models.SuppressionrulesUpdateSuppressionRuleRequest{
		ID:                        rule.ID.ValueStringPointer(),
		Name:                      rule.Name.ValueString(),
		RuleSelectionType:         rule.RuleSelectionType.ValueString(),
		ScopeType:                 rule.ScopeType.ValueString(),
		SuppressionComment:        rule.SuppressionComment.ValueString(),
		SuppressionExpirationDate: rule.SuppressionExpirationDate.ValueString(),
		SuppressionReason:         rule.SuppressionReason.ValueString(),
	}

	if rule.RuleSelectionType.ValueString() == "rule_selection_filter" {
		ruleSelectionFilter, diags := createSuppressionRuleSelectionFilter(ctx, *rule.RuleSelectionFilter)
		if diags.HasError() {
			return nil, diags
		}

		body.RuleSelectionFilter = ruleSelectionFilter
	}

	if rule.ScopeType.ValueString() == "asset_filter" {
		scopeAssetFilter, diags := createSuppressionrulesScopeAssetFilter(ctx, *rule.ScopeAssetFilter)
		if diags.HasError() {
			return nil, diags
		}

		body.ScopeAssetFilter = scopeAssetFilter
	}

	params := cloud_policies.UpdateSuppressionRuleParams{
		Context: ctx,
		Body:    &body,
	}

	resp, err := r.client.CloudPolicies.UpdateSuppressionRule(&params)
	if err != nil {
		if badRequest, ok := err.(*cloud_policies.UpdateSuppressionRuleBadRequest); ok {
			diags.AddError(
				"Error Updating Suppression Rule",
				fmt.Sprintf("Failed to update suppression rule (400): %s, %+v", rule.ID.ValueString(), *badRequest.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		if internalServerError, ok := err.(*cloud_policies.UpdateSuppressionRuleInternalServerError); ok {
			diags.AddError(
				"Error Updating Suppression Rule",
				fmt.Sprintf("Failed to update suppression rule (500): %s, %+v", rule.ID.ValueString(), *internalServerError.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		diags.AddError(
			"Error Updating Suppression Rule",
			fmt.Sprintf("Failed to update suppression rule %s: %+v", rule.ID.ValueString(), err),
		)

		return nil, diags
	}

	if resp == nil || resp.Payload == nil || len(resp.Payload.Resources) == 0 {
		diags.AddError(
			"Error Updating Rule",
			fmt.Sprintf("Failed to update rule %s: API returned an empty response", rule.ID.ValueString()),
		)
		return nil, diags
	}

	payload := resp.GetPayload()

	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.AddError(
			"Error Updating Suppression Rule",
			fmt.Sprintf("Failed to update suppression rule: %s", err.Error()),
		)
		return nil, diags
	}

	return payload.Resources[0], diags
}

func (r *cloudSecuritySuppressionRuleResource) deleteSuppressionRule(ctx context.Context, id string) diag.Diagnostics {
	var diags diag.Diagnostics

	params := cloud_policies.DeleteSuppressionRulesParams{
		Context: ctx,
		Ids:     []string{id},
	}

	_, err := r.client.CloudPolicies.DeleteSuppressionRules(&params)
	if err != nil {
		diags.AddError(
			"Error Deleting Rule",
			fmt.Sprintf("Failed to delete rule %s: \n\n %s", id, err.Error()),
		)
	}

	return diags
}

func createSuppressionRuleSelectionFilter(ctx context.Context, filter ruleSelectionFilterModel) (*models.SuppressionrulesRuleSelectionFilter, diag.Diagnostics) {
	var ruleSelectionFilter models.SuppressionrulesRuleSelectionFilter
	var diags diag.Diagnostics

	diags = filter.RuleIds.ElementsAs(ctx, &ruleSelectionFilter.RuleIds, false)
	if diags.HasError() {
		return nil, diags
	}

	diags = filter.RuleNames.ElementsAs(ctx, &ruleSelectionFilter.RuleNames, false)
	if diags.HasError() {
		return nil, diags
	}

	diags = filter.RuleOrigins.ElementsAs(ctx, &ruleSelectionFilter.RuleOrigins, false)
	if diags.HasError() {
		return nil, diags
	}

	diags = filter.RuleProviders.ElementsAs(ctx, &ruleSelectionFilter.RuleProviders, false)
	if diags.HasError() {
		return nil, diags
	}

	diags = filter.RuleServices.ElementsAs(ctx, &ruleSelectionFilter.RuleServices, false)
	if diags.HasError() {
		return nil, diags
	}

	diags = filter.RuleSeverities.ElementsAs(ctx, &ruleSelectionFilter.RuleSeverities, false)
	if diags.HasError() {
		return nil, diags
	}

	var convertedRuleSeverities []string
	for _, severity := range ruleSelectionFilter.RuleSeverities {
		convertedRuleSeverities = append(convertedRuleSeverities, severityToString[severity])
	}

	ruleSelectionFilter.RuleSeverities = convertedRuleSeverities

	return &ruleSelectionFilter, diags
}

func createSuppressionrulesScopeAssetFilter(ctx context.Context, filter scopeAssetFilterModel) (*models.SuppressionrulesScopeAssetFilter, diag.Diagnostics) {
	var scopeAssetFilter models.SuppressionrulesScopeAssetFilter
	var diags diag.Diagnostics

	diags = filter.AccountIds.ElementsAs(ctx, &scopeAssetFilter.AccountIds, false)
	if diags.HasError() {
		return nil, diags
	}

	diags = filter.CloudGroupIds.ElementsAs(ctx, &scopeAssetFilter.CloudGroupIds, false)
	if diags.HasError() {
		return nil, diags
	}

	diags = filter.CloudProviders.ElementsAs(ctx, &scopeAssetFilter.CloudProviders, false)
	if diags.HasError() {
		return nil, diags
	}

	diags = filter.Regions.ElementsAs(ctx, &scopeAssetFilter.Regions, false)
	if diags.HasError() {
		return nil, diags
	}

	diags = filter.ResourceIds.ElementsAs(ctx, &scopeAssetFilter.ResourceIds, false)
	if diags.HasError() {
		return nil, diags
	}

	diags = filter.ResourceNames.ElementsAs(ctx, &scopeAssetFilter.ResourceNames, false)
	if diags.HasError() {
		return nil, diags
	}

	diags = filter.ResourceTypes.ElementsAs(ctx, &scopeAssetFilter.ResourceTypes, false)
	if diags.HasError() {
		return nil, diags
	}

	diags = filter.ServiceCategories.ElementsAs(ctx, &scopeAssetFilter.ServiceCategories, false)
	if diags.HasError() {
		return nil, diags
	}

	diags = filter.Tags.ElementsAs(ctx, &scopeAssetFilter.Tags, false)
	if diags.HasError() {
		return nil, diags
	}

	return &scopeAssetFilter, diags
}
