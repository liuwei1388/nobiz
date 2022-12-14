<script lang="ts" setup>
import {
  IconArrowDown,
  IconMessage,
  VButton,
  VCard,
  VPageHeader,
  VPagination,
  VSpace,
  IconCloseCircle,
  IconRefreshLine,
  VEmpty,
  Dialog,
} from "@halo-dev/components";
import CommentListItem from "./components/CommentListItem.vue";
import UserDropdownSelector from "@/components/dropdown-selector/UserDropdownSelector.vue";
import type {
  ListedComment,
  ListedCommentList,
  User,
} from "@halo-dev/api-client";
import { onMounted, ref, watch } from "vue";
import { apiClient } from "@/utils/api-client";
import { onBeforeRouteLeave } from "vue-router";

const comments = ref<ListedCommentList>({
  page: 1,
  size: 20,
  total: 0,
  items: [],
  first: true,
  last: false,
  hasNext: false,
  hasPrevious: false,
});
const loading = ref(false);
const checkAll = ref(false);
const selectedComment = ref<ListedComment>();
const selectedCommentNames = ref<string[]>([]);
const keyword = ref("");
const refreshInterval = ref();

const handleFetchComments = async () => {
  try {
    clearInterval(refreshInterval.value);

    loading.value = true;
    const { data } = await apiClient.comment.listComments({
      page: comments.value.page,
      size: comments.value.size,
      approved: selectedApprovedFilterItem.value.value,
      sort: selectedSortFilterItem.value.value,
      keyword: keyword.value,
      ownerName: selectedUser.value?.metadata.name,
    });
    comments.value = data;

    const deletedComments = comments.value.items.filter(
      (comment) => !!comment.comment.metadata.deletionTimestamp
    );

    if (deletedComments.length) {
      refreshInterval.value = setInterval(() => {
        handleFetchComments();
      }, 3000);
    }
  } catch (error) {
    console.log("Failed to fetch comments", error);
  } finally {
    loading.value = false;
  }
};

onBeforeRouteLeave(() => {
  clearInterval(refreshInterval.value);
});

const handlePaginationChange = ({
  page,
  size,
}: {
  page: number;
  size: number;
}) => {
  comments.value.page = page;
  comments.value.size = size;
  handleFetchComments();
};

// Selection
const handleCheckAllChange = (e: Event) => {
  const { checked } = e.target as HTMLInputElement;

  if (checked) {
    selectedCommentNames.value =
      comments.value.items.map((comment) => {
        return comment.comment.metadata.name;
      }) || [];
  } else {
    selectedCommentNames.value = [];
  }
};

const checkSelection = (comment: ListedComment) => {
  return (
    comment.comment.metadata.name ===
      selectedComment.value?.comment.metadata.name ||
    selectedCommentNames.value.includes(comment.comment.metadata.name)
  );
};

watch(
  () => selectedCommentNames.value,
  (newValue) => {
    checkAll.value = newValue.length === comments.value.items?.length;
  }
);

const handleDeleteInBatch = async () => {
  Dialog.warning({
    title: "????????????????????????????????????",
    description: "??????????????????????????????????????????????????????????????????",
    confirmType: "danger",
    onConfirm: async () => {
      try {
        const promises = selectedCommentNames.value.map((name) => {
          return apiClient.extension.comment.deletecontentHaloRunV1alpha1Comment(
            {
              name,
            }
          );
        });
        await Promise.all(promises);
        selectedCommentNames.value = [];
      } catch (e) {
        console.error("Failed to delete comments", e);
      } finally {
        await handleFetchComments();
      }
    },
  });
};

const handleApproveInBatch = async () => {
  Dialog.warning({
    title: "???????????????????????????????????????",
    onConfirm: async () => {
      try {
        const commentsToUpdate = comments.value.items.filter((comment) => {
          return (
            selectedCommentNames.value.includes(
              comment.comment.metadata.name
            ) && !comment.comment.spec.approved
          );
        });
        const promises = commentsToUpdate.map((comment) => {
          const commentToUpdate = comment.comment;
          commentToUpdate.spec.approved = true;
          return apiClient.extension.comment.updatecontentHaloRunV1alpha1Comment(
            {
              name: commentToUpdate.metadata.name,
              comment: commentToUpdate,
            }
          );
        });
        await Promise.all(promises);
        selectedCommentNames.value = [];
      } catch (e) {
        console.error("Failed to approve comments in batch", e);
      } finally {
        await handleFetchComments();
      }
    },
  });
};

onMounted(handleFetchComments);

// Filters
const ApprovedFilterItems: { label: string; value?: boolean }[] = [
  {
    label: "??????",
    value: undefined,
  },
  {
    label: "?????????",
    value: true,
  },
  {
    label: "?????????",
    value: false,
  },
];

type Sort = "LAST_REPLY_TIME" | "REPLY_COUNT" | "CREATE_TIME";

const SortFilterItems: {
  label: string;
  value?: Sort;
}[] = [
  {
    label: "??????",
    value: "LAST_REPLY_TIME",
  },
  {
    label: "?????????",
    value: "REPLY_COUNT",
  },
  {
    label: "????????????",
    value: "CREATE_TIME",
  },
];
const selectedApprovedFilterItem = ref<{ label: string; value?: boolean }>(
  ApprovedFilterItems[0]
);
const selectedSortFilterItem = ref<{
  label: string;
  value?: Sort;
}>(SortFilterItems[0]);
const selectedUser = ref<User>();

const handleApprovedFilterItemChange = (filterItem: {
  label: string;
  value?: boolean;
}) => {
  selectedApprovedFilterItem.value = filterItem;
  selectedCommentNames.value = [];
  handlePaginationChange({ page: 1, size: 20 });
};

const handleSortFilterItemChange = (filterItem: {
  label: string;
  value?: Sort;
}) => {
  selectedSortFilterItem.value = filterItem;
  selectedCommentNames.value = [];
  handlePaginationChange({ page: 1, size: 20 });
};

function handleSelectUser(user: User | undefined) {
  selectedUser.value = user;
  handlePaginationChange({ page: 1, size: 20 });
}
</script>
<template>
  <VPageHeader title="??????">
    <template #icon>
      <IconMessage class="mr-2 self-center" />
    </template>
  </VPageHeader>

  <div class="m-0 md:m-4">
    <VCard :body-class="['!p-0']">
      <template #header>
        <div class="block w-full bg-gray-50 px-4 py-3">
          <div
            class="relative flex flex-col items-start sm:flex-row sm:items-center"
          >
            <div
              v-permission="['system:comments:manage']"
              class="mr-4 hidden items-center sm:flex"
            >
              <input
                v-model="checkAll"
                class="h-4 w-4 rounded border-gray-300 text-indigo-600"
                type="checkbox"
                @change="handleCheckAllChange"
              />
            </div>
            <div class="flex w-full flex-1 items-center sm:w-auto">
              <div
                v-if="!selectedCommentNames.length"
                class="flex items-center gap-2"
              >
                <FormKit
                  v-model="keyword"
                  placeholder="?????????????????????"
                  type="text"
                  @keyup.enter="handleFetchComments"
                ></FormKit>
                <div
                  v-if="selectedApprovedFilterItem.value != undefined"
                  class="group flex cursor-pointer items-center justify-center gap-1 rounded-full bg-gray-200 px-2 py-1 hover:bg-gray-300"
                >
                  <span class="text-xs text-gray-600 group-hover:text-gray-900">
                    ?????????{{ selectedApprovedFilterItem.label }}
                  </span>
                  <IconCloseCircle
                    class="h-4 w-4 text-gray-600"
                    @click="
                      handleApprovedFilterItemChange(ApprovedFilterItems[0])
                    "
                  />
                </div>
                <div
                  v-if="selectedUser"
                  class="group flex cursor-pointer items-center justify-center gap-1 rounded-full bg-gray-200 px-2 py-1 hover:bg-gray-300"
                >
                  <span class="text-xs text-gray-600 group-hover:text-gray-900">
                    ????????????{{ selectedUser?.spec.displayName }}
                  </span>
                  <IconCloseCircle
                    class="h-4 w-4 text-gray-600"
                    @click="handleSelectUser(undefined)"
                  />
                </div>
                <div
                  v-if="selectedSortFilterItem.value != 'LAST_REPLY_TIME'"
                  class="group flex cursor-pointer items-center justify-center gap-1 rounded-full bg-gray-200 px-2 py-1 hover:bg-gray-300"
                >
                  <span class="text-xs text-gray-600 group-hover:text-gray-900">
                    ?????????{{ selectedSortFilterItem.label }}
                  </span>
                  <IconCloseCircle
                    class="h-4 w-4 text-gray-600"
                    @click="handleSortFilterItemChange(SortFilterItems[0])"
                  />
                </div>
              </div>
              <VSpace v-else>
                <VButton type="secondary" @click="handleApproveInBatch">
                  ????????????
                </VButton>
                <VButton type="danger" @click="handleDeleteInBatch">
                  ??????
                </VButton>
              </VSpace>
            </div>
            <div class="mt-4 flex sm:mt-0">
              <VSpace spacing="lg">
                <FloatingDropdown>
                  <div
                    class="flex cursor-pointer select-none items-center text-sm text-gray-700 hover:text-black"
                  >
                    <span class="mr-0.5"> ?????? </span>
                    <span>
                      <IconArrowDown />
                    </span>
                  </div>
                  <template #popper>
                    <div class="w-72 p-4">
                      <ul class="space-y-1">
                        <li
                          v-for="(filterItem, index) in ApprovedFilterItems"
                          :key="index"
                          v-close-popper
                          :class="{
                            'bg-gray-100':
                              selectedApprovedFilterItem.value ===
                              filterItem.value,
                          }"
                          class="flex cursor-pointer items-center rounded px-3 py-2 text-sm text-gray-600 hover:bg-gray-100 hover:text-gray-900"
                          @click="handleApprovedFilterItemChange(filterItem)"
                        >
                          <span class="truncate">
                            {{ filterItem.label }}
                          </span>
                        </li>
                      </ul>
                    </div>
                  </template>
                </FloatingDropdown>
                <UserDropdownSelector
                  v-model:selected="selectedUser"
                  @select="handleSelectUser"
                >
                  <div
                    class="flex cursor-pointer select-none items-center text-sm text-gray-700 hover:text-black"
                  >
                    <span class="mr-0.5">?????????</span>
                    <span>
                      <IconArrowDown />
                    </span>
                  </div>
                </UserDropdownSelector>
                <FloatingDropdown>
                  <div
                    class="flex cursor-pointer select-none items-center text-sm text-gray-700 hover:text-black"
                  >
                    <span class="mr-0.5"> ?????? </span>
                    <span>
                      <IconArrowDown />
                    </span>
                  </div>
                  <template #popper>
                    <div class="w-72 p-4">
                      <ul class="space-y-1">
                        <li
                          v-for="(filterItem, index) in SortFilterItems"
                          :key="index"
                          v-close-popper
                          :class="{
                            'bg-gray-100':
                              selectedSortFilterItem.value === filterItem.value,
                          }"
                          class="flex cursor-pointer items-center rounded px-3 py-2 text-sm text-gray-600 hover:bg-gray-100 hover:text-gray-900"
                          @click="handleSortFilterItemChange(filterItem)"
                        >
                          <span class="truncate">
                            {{ filterItem.label }}
                          </span>
                        </li>
                      </ul>
                    </div>
                  </template>
                </FloatingDropdown>
                <div class="flex flex-row gap-2">
                  <div
                    class="group cursor-pointer rounded p-1 hover:bg-gray-200"
                    @click="handleFetchComments"
                  >
                    <IconRefreshLine
                      :class="{ 'animate-spin text-gray-900': loading }"
                      class="h-4 w-4 text-gray-600 group-hover:text-gray-900"
                    />
                  </div>
                </div>
              </VSpace>
            </div>
          </div>
        </div>
      </template>
      <VEmpty
        v-if="!comments.items.length && !loading"
        message="?????????????????????????????????????????????"
        title="??????????????????"
      >
        <template #actions>
          <VSpace>
            <VButton @click="handleFetchComments">??????</VButton>
          </VSpace>
        </template>
      </VEmpty>
      <ul class="box-border h-full w-full divide-y divide-gray-100" role="list">
        <li v-for="(comment, index) in comments.items" :key="index">
          <CommentListItem
            :comment="comment"
            :is-selected="checkSelection(comment)"
            @reload="handleFetchComments"
          >
            <template #checkbox>
              <input
                v-model="selectedCommentNames"
                :value="comment?.comment?.metadata.name"
                class="h-4 w-4 rounded border-gray-300 text-indigo-600"
                name="comment-checkbox"
                type="checkbox"
              />
            </template>
          </CommentListItem>
        </li>
      </ul>

      <template #footer>
        <div class="bg-white sm:flex sm:items-center sm:justify-end">
          <VPagination
            :page="comments.page"
            :size="comments.size"
            :total="comments.total"
            :size-options="[20, 30, 50, 100]"
            @change="handlePaginationChange"
          />
        </div>
      </template>
    </VCard>
  </div>
</template>
