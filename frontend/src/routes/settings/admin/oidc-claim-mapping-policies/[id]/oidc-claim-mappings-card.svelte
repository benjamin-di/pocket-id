<script lang="ts">
	import * as Card from '#lib/components/ui/card/index.ts';
	import { Button } from '#lib/components/ui/button/index.ts';
	import { m } from '#lib/paraglide/messages.js';
	import ApisService from '#lib/services/apis-service.ts';
	import CustomClaimService from '#lib/services/custom-claim-service.ts';
	import type {
		OidcClaimMappingDto,
		OidcClaimMappingPolicySourceType,
		OidcUserField
	} from '#lib/types/oidc-claim-mapping-policy.type.ts';
	import { LucidePencil, LucideTrash } from '@lucide/svelte';
	import AdvancedTable from '#lib/components/table/advanced-table.svelte';
	import type { AdvancedTableColumn } from '#lib/types/advanced-table.type.ts';
	import type { ListRequestOptions, Paginated } from '#lib/types/list-request.type.ts';
	import { onMount } from 'svelte';
	import OidcClaimMappingModal from './oidc-claim-mapping-modal.svelte';

	let {
		policyId,
		claimMappings = $bindable(),
		readOnly = false
	}: {
		policyId: string;
		claimMappings: OidcClaimMappingDto[];
		readOnly?: boolean;
	} = $props();

	type OidcClaimMappingRow = OidcClaimMappingDto & { id: string };

	let tableRef: AdvancedTable<OidcClaimMappingRow>;
	let editing = $state<OidcClaimMappingDto | null>(null);
	let modalOpen = $state(false);
	let editingIndex = $state(-1);
	let editingKey = $state(0);

	let apiScopes = $state<string[]>([]);
	let customClaimKeysSuggestions = $state<string[]>([]);

	onMount(() => {
		if (readOnly) return;
		new ApisService()
			.listAll()
			.then((apis) => {
				apiScopes = apis.flatMap((api) => api.permissions.map((permission) => permission.key));
			})
			.catch(() => {
				/* Keep standard and already selected scopes available when API listing is unavailable */
			});
		new CustomClaimService()
			.getSuggestions()
			.then((data) => {
				customClaimKeysSuggestions = data;
			})
			.catch(() => {
				/* Keep custom claim input functional when suggestions fail to load */
			});
	});

	export function refresh() {
		return tableRef?.refresh();
	}

	function addClaimMapping() {
		editing = {
			claimName: '',
			sourceType: 'user_field',
			sourceValue: '',
			scope: ['profile'],
			accessToken: false,
			idToken: true,
			userInfo: true
		};
		editingIndex = -1;
		editingKey++;
		modalOpen = true;
	}

	function editClaimMapping(item: OidcClaimMappingRow) {
		const { id, ...mapping } = item;
		editing = mapping;
		editingIndex = Number(id);
		editingKey++;
		modalOpen = true;
	}

	async function onSaveClaimMapping(mapping: OidcClaimMappingDto, index: number) {
		modalOpen = false;
		editing = null;
		editingIndex = -1;
		claimMappings =
			index === -1
				? [...claimMappings, mapping]
				: claimMappings.map((entry, i) => (i === index ? mapping : entry));
		await tableRef?.refresh();
	}

	async function removeClaimMapping(index: string) {
		const target = Number(index);
		claimMappings = claimMappings.filter((_, i) => i !== target);
		await tableRef?.refresh();
	}

	const existingClaimNamesForModal = $derived(
		claimMappings.filter((_, i) => i !== editingIndex).map((entry) => entry.claimName)
	);

	function getSourceTypeLabel(field: OidcClaimMappingPolicySourceType): string {
		const labels: Record<OidcClaimMappingPolicySourceType, string> = {
			user_field: m.user_field(),
			custom_claim: m.custom_claims(),
			static: m.static_value()
		};
		return labels[field] || field;
	}

	function getUserFieldLabel(field: OidcUserField): string {
		const labels: Record<OidcUserField, string> = {
			id: m.user_identifier(),
			email: m.email(),
			email_verified: m.email_verified(),
			first_name: m.first_name(),
			last_name: m.last_name(),
			full_name: m.full_name(),
			display_name: m.display_name(),
			username: m.username(),
			locale: m.locale(),
			picture: m.profile_picture(),
			groups: m.groups()
		};
		return labels[field] || field;
	}

	const columns: AdvancedTableColumn<OidcClaimMappingRow>[] = [
		{ label: m.claim_name(), column: 'claimName' },
		{ label: m.source_type(), key: 'sourceType', cell: OidcClaimMappingSourceTypeCell },
		{ label: m.source_value(), key: 'sourceValue', cell: OidcClaimMappingSourceValueCell },
		{ label: m.scope(), column: 'scope', hidden: true },
		{ label: m.access_token(), column: 'accessToken', hidden: true },
		{ label: m.id_token(), column: 'idToken', hidden: true },
		{ label: m.userinfo(), column: 'userInfo', hidden: true },
		...(readOnly ? [] : [{ label: '', key: 'actions', cell: OidcClaimMappingActionsCell }])
	];

	async function fetchCallback(
		options: ListRequestOptions
	): Promise<Paginated<OidcClaimMappingRow>> {
		const limit = options.pagination?.limit || 20;
		const totalItems = claimMappings.length;
		const totalPages = Math.max(1, Math.ceil(totalItems / limit));
		const page = Math.min(Math.max(options.pagination?.page || 1, 1), totalPages);
		return {
			data: claimMappings
				.map((entry, index) => ({ ...entry, id: String(index) }))
				.slice((page - 1) * limit, page * limit),
			pagination: {
				currentPage: page,
				itemsPerPage: limit,
				totalItems,
				totalPages
			}
		};
	}
</script>

{#snippet OidcClaimMappingSourceTypeCell({ item }: { item: OidcClaimMappingRow })}
	{getSourceTypeLabel(item.sourceType as OidcClaimMappingPolicySourceType)}
{/snippet}

{#snippet OidcClaimMappingSourceValueCell({ item }: { item: OidcClaimMappingRow })}
	{#if item.sourceType === 'user_field'}
		{getUserFieldLabel(item.sourceValue as OidcUserField)}
	{:else if item.sourceType === 'custom_claim' || item.sourceType === 'static'}
		{item.sourceValue}
	{/if}
{/snippet}

{#snippet OidcClaimMappingActionsCell({ item }: { item: OidcClaimMappingRow })}
	<div class="flex justify-end gap-1">
		<Button
			variant="ghost"
			size="sm"
			aria-label={m.edit()}
			onclick={(e: MouseEvent) => {
				e.stopPropagation();
				editClaimMapping(item);
			}}
		>
			<LucidePencil class="size-4" />
		</Button>
		<Button
			variant="ghost"
			size="sm"
			aria-label={m.remove_claim_mapping()}
			onclick={(e: MouseEvent) => {
				e.stopPropagation();
				removeClaimMapping(item.id);
			}}
		>
			<LucideTrash class="size-4" />
		</Button>
	</div>
{/snippet}

<Card.Root>
	<Card.Header>
		<div class="flex flex-wrap items-center justify-between gap-4 md:flex-nowrap">
			<div>
				<Card.Title>{m.claim_mappings()}</Card.Title>
				<Card.Description>
					{readOnly ? m.built_in_claim_mappings_description() : m.claim_mappings_description()}
				</Card.Description>
			</div>
			{#if !readOnly}
				<Button class="w-full md:w-auto" onclick={addClaimMapping}>{m.add_claim_mapping()}</Button>
			{/if}
		</div>
	</Card.Header>
	<Card.Content>
		<AdvancedTable
			id={`claim-mappings-${policyId}`}
			bind:this={tableRef}
			withoutSearch
			{fetchCallback}
			{columns}
			onRowClick={readOnly ? undefined : (item) => editClaimMapping(item)}
		/>
	</Card.Content>
</Card.Root>

{#if editing}
	{#key editingKey}
		<OidcClaimMappingModal
			index={editingIndex}
			mapping={editing}
			existingClaimNames={existingClaimNamesForModal}
			{apiScopes}
			{customClaimKeysSuggestions}
			onSave={onSaveClaimMapping}
			bind:open={modalOpen}
		/>
	{/key}
{/if}
