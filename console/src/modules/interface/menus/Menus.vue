<script lang="ts" setup>
import {
  IconAddCircle,
  IconListSettings,
  Dialog,
  VButton,
  VCard,
  VEmpty,
  VPageHeader,
  VSpace,
} from "@halo-dev/components";
import MenuItemEditingModal from "./components/MenuItemEditingModal.vue";
import MenuItemListItem from "./components/MenuItemListItem.vue";
import MenuList from "./components/MenuList.vue";
import { onUnmounted, ref } from "vue";
import { apiClient } from "@/utils/api-client";
import type { Menu, MenuItem } from "@halo-dev/api-client";
import cloneDeep from "lodash.clonedeep";
import type { MenuTreeItem } from "./utils";
import {
  buildMenuItemsTree,
  convertMenuTreeItemToMenuItem,
  convertTreeToMenuItems,
  getChildrenNames,
  resetMenuItemsTreePriority,
} from "./utils";
import { useDebounceFn } from "@vueuse/core";
import { onBeforeRouteLeave } from "vue-router";

const menuItems = ref<MenuItem[]>([] as MenuItem[]);
const menuTreeItems = ref<MenuTreeItem[]>([] as MenuTreeItem[]);
const selectedMenu = ref<Menu>();
const selectedMenuItem = ref<MenuItem>();
const selectedParentMenuItem = ref<MenuItem>();
const loading = ref(false);
const menuListRef = ref();
const menuItemEditingModal = ref();
const refreshInterval = ref();

const handleFetchMenuItems = async () => {
  try {
    clearInterval(refreshInterval.value);

    loading.value = true;

    if (!selectedMenu.value?.spec.menuItems) {
      return;
    }
    const menuItemNames = Array.from(selectedMenu.value.spec.menuItems)?.map(
      (item) => item
    );
    const { data } = await apiClient.extension.menuItem.listv1alpha1MenuItem({
      page: 0,
      size: 0,
      fieldSelector: [`name=(${menuItemNames.join(",")})`],
    });
    menuItems.value = data.items;
    // Build the menu tree
    menuTreeItems.value = buildMenuItemsTree(data.items);

    const deletedMenuItems = menuItems.value.filter(
      (menuItem) => !!menuItem.metadata.deletionTimestamp
    );

    if (deletedMenuItems.length) {
      refreshInterval.value = setInterval(() => {
        handleFetchMenuItems();
      }, 3000);
    }
  } catch (e) {
    console.error("Failed to fetch menu items", e);
  } finally {
    loading.value = false;
  }
};

onUnmounted(() => {
  clearInterval(refreshInterval.value);
});

onBeforeRouteLeave(() => {
  clearInterval(refreshInterval.value);
});

const handleOpenEditingModal = (menuItem: MenuTreeItem) => {
  selectedMenuItem.value = convertMenuTreeItemToMenuItem(menuItem);
  menuItemEditingModal.value = true;
};

const handleOpenCreateByParentModal = (menuItem: MenuTreeItem) => {
  selectedParentMenuItem.value = convertMenuTreeItemToMenuItem(menuItem);
  menuItemEditingModal.value = true;
};

const onMenuItemEditingModalClose = () => {
  selectedParentMenuItem.value = undefined;
  selectedMenuItem.value = undefined;
};

const onMenuItemSaved = async (menuItem: MenuItem) => {
  const menuToUpdate = cloneDeep(selectedMenu.value);

  if (menuToUpdate) {
    const menuItemsToUpdate = cloneDeep(menuToUpdate.spec.menuItems) || [];
    menuItemsToUpdate.push(menuItem.metadata.name);

    menuToUpdate.spec.menuItems = menuItemsToUpdate;
    await apiClient.extension.menu.updatev1alpha1Menu({
      name: menuToUpdate.metadata.name,
      menu: menuToUpdate,
    });
  }

  await menuListRef.value.handleFetchMenus();
  await handleFetchMenuItems();
};

const handleUpdateInBatch = useDebounceFn(async () => {
  const menuTreeItemsToUpdate = resetMenuItemsTreePriority(menuTreeItems.value);
  const menuItemsToUpdate = convertTreeToMenuItems(menuTreeItemsToUpdate);
  try {
    const promises = menuItemsToUpdate.map((menuItem) =>
      apiClient.extension.menuItem.updatev1alpha1MenuItem({
        name: menuItem.metadata.name,
        menuItem,
      })
    );
    await Promise.all(promises);
  } catch (e) {
    console.log("Failed to update menu items", e);
  } finally {
    await menuListRef.value.handleFetchMenus();
    await handleFetchMenuItems();
  }
}, 500);

const handleDelete = async (menuItem: MenuTreeItem) => {
  Dialog.info({
    title: "??????????????????????????????",
    description: "????????????????????????",
    confirmType: "danger",
    onConfirm: async () => {
      await apiClient.extension.menuItem.deletev1alpha1MenuItem({
        name: menuItem.metadata.name,
      });

      const childrenNames = getChildrenNames(menuItem);

      if (childrenNames.length) {
        setTimeout(() => {
          Dialog.info({
            title: "?????????????????????????????????????????????????????????",
            description: "???????????????????????????????????????????????????????????????",
            confirmType: "danger",
            onConfirm: async () => {
              const promises = childrenNames.map((name) =>
                apiClient.extension.menuItem.deletev1alpha1MenuItem({
                  name,
                })
              );
              await Promise.all(promises);
            },
          });
        }, 200);
      }

      await menuListRef.value.handleFetchMenus();
      await handleFetchMenuItems();
    },
  });
};
</script>
<template>
  <MenuItemEditingModal
    v-model:visible="menuItemEditingModal"
    :menu-item="selectedMenuItem"
    :parent-menu-item="selectedParentMenuItem"
    :menu="selectedMenu"
    @close="onMenuItemEditingModalClose"
    @saved="onMenuItemSaved"
  />
  <VPageHeader title="??????">
    <template #icon>
      <IconListSettings class="mr-2 self-center" />
    </template>
  </VPageHeader>
  <div class="m-0 md:m-4">
    <div class="flex flex-col gap-4 sm:flex-row">
      <div class="w-96">
        <MenuList
          ref="menuListRef"
          v-model:selected-menu="selectedMenu"
          @select="handleFetchMenuItems"
        />
      </div>
      <div class="flex-1">
        <VCard :body-class="['!p-0']">
          <template #header>
            <div class="block w-full bg-gray-50 px-4 py-3">
              <div
                class="relative flex flex-col items-start sm:flex-row sm:items-center"
              >
                <div class="flex w-full flex-1 sm:w-auto">
                  <span class="text-base font-medium">
                    {{ selectedMenu?.spec.displayName }}
                  </span>
                </div>
                <div class="mt-4 flex sm:mt-0">
                  <VSpace>
                    <VButton
                      v-permission="['system:menus:manage']"
                      size="xs"
                      type="default"
                      @click="menuItemEditingModal = true"
                    >
                      ??????
                    </VButton>
                  </VSpace>
                </div>
              </div>
            </div>
          </template>
          <VEmpty
            v-if="!menuItems.length && !loading"
            message="??????????????????????????????????????????"
            title="?????????????????????"
          >
            <template #actions>
              <VSpace>
                <VButton @click="handleFetchMenuItems"> ??????</VButton>
                <VButton
                  v-permission="['system:menus:manage']"
                  type="primary"
                  @click="menuItemEditingModal = true"
                >
                  <template #icon>
                    <IconAddCircle class="h-full w-full" />
                  </template>
                  ???????????????
                </VButton>
              </VSpace>
            </template>
          </VEmpty>
          <MenuItemListItem
            v-else
            :menu-tree-items="menuTreeItems"
            @change="handleUpdateInBatch"
            @delete="handleDelete"
            @open-editing="handleOpenEditingModal"
            @open-create-by-parent="handleOpenCreateByParentModal"
          />
        </VCard>
      </div>
    </div>
  </div>
</template>
