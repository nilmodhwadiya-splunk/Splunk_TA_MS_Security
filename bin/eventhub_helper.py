##
# SPDX-FileCopyrightText: 2023 Splunk, Inc. <sales@splunk.com>
# SPDX-License-Identifier: LicenseRef-Splunk-8-2021
##
##

import import_declare_test  # noqa: F401
import time
import json
import logging
import uuid
import traceback
from threading import Thread

from splunklib import modularinput as smi
from solnlib.modular_input import checkpointer
from solnlib import log
import splunk_ta_ms_security_constants
from ta_execution_exception import TaExecutionException
from ms_security_utils import (
    get_account_details,
    get_proxy_dict_for_eventhub,
    delete_checkpoint,
)
from splunktaucclib.rest_handler.error import RestError

from azure.identity import ClientSecretCredential
from azure.eventhub import EventHubConsumerClient, CheckpointStore
from azure.eventhub import exceptions as azure_exceptions

APP_NAME = import_declare_test.ta_name
CHECKPOINTER = splunk_ta_ms_security_constants.CHECKPOINTER
EVENT_HUB_INPUT_TYPE = splunk_ta_ms_security_constants.EVENT_HUB_INPUT_TYPE
LOG_FILE_NAME = splunk_ta_ms_security_constants.EVENT_HUB_LOG_FILE_NAME
CURR_EVENT_BATCH_STATS = splunk_ta_ms_security_constants.CURR_EVENT_BATCH_STATS
TOTAL_EVENT_BATCH_STATS = splunk_ta_ms_security_constants.TOTAL_EVENT_BATCH_STATS
EH_NAMESPACE_ERROR = splunk_ta_ms_security_constants.EH_NAMESPACE_ERROR
EH_NAME_ERROR = splunk_ta_ms_security_constants.EH_NAME_ERROR
EH_FAILED_TO_CREATE_MSG = splunk_ta_ms_security_constants.EH_FAILED_TO_CREATE_MSG
EH_ERROR_SPECIFIC_MSG = splunk_ta_ms_security_constants.EH_ERROR_SPECIFIC_MSG
EH_ERROR_GENERAL_MSG = splunk_ta_ms_security_constants.EH_ERROR_GENERAL_MSG


def get_azure_event_hub_credentials(
    logger: logging.Logger, global_account: dict, proxies: dict
):
    """returns azure event hub credentials

    Args:
        logger (logging.Logger): logger
        global_account (dict): azure app account for which credentials will be generated
        proxies (dict): proxy

    Returns:
        credential: azure event hub credentials
    """
    try:
        credential = ClientSecretCredential(
            global_account["tenant_id"],
            global_account["username"],
            global_account["password"],
            proxies=proxies,
        )
        logger.debug("Event hub credentials retrieved successfully")
        return credential

    except Exception as e:
        logger.error(
            f"Exception occurred while retrieving azure event hub credentials, reason={e}"
        )
        return None


def raise_user_readable_rest_error(exception) -> RestError:
    """raises user friendly RestError for better readability

    Args:
        exception (exception): exception

    Raises:
        RestError: RestError with proper message
    """
    err = exception.error
    msg = exception.message.split("\n")[0]

    # if error message is not ending with ".", append "."
    if msg[-1] != ".":
        msg += "."

    if msg == EH_NAMESPACE_ERROR:
        raise RestError(
            400,
            EH_ERROR_SPECIFIC_MSG.format(
                err, msg, "Event Hub Namespace", LOG_FILE_NAME
            ),
        )
    if msg == EH_NAME_ERROR:
        raise RestError(
            400, EH_ERROR_SPECIFIC_MSG.format(err, msg, "Event Hub Name", LOG_FILE_NAME)
        )
    raise RestError(400, EH_ERROR_GENERAL_MSG.format(err, msg, LOG_FILE_NAME))


def event_hub_consumer_validation(
    payload: dict, session_key: str, log_file_name: str
) -> None:
    """
    Validates account credentials are valid or not

    Args:
        payload (dict): input details
        session_key (str): session key
        log_file_name (str): log file name

    Raises:
        RestError: error to be displayed to user
    """
    logger = log.Logs().get_logger(log_file_name)
    global_account = get_account_details(
        logger, session_key, payload["azure_app_account"]
    )
    proxies = get_proxy_dict_for_eventhub(logger, session_key)
    credential = get_azure_event_hub_credentials(logger, global_account, proxies)

    if not credential:
        raise RestError(400, "Not able to retrieve Azure Eventhub credentials")

    try:
        consumer = EventHubConsumerClient(
            fully_qualified_namespace=payload["event_hub_namespace"],
            eventhub_name=payload["event_hub_name"],
            consumer_group=payload["consumer_group"],
            credential=credential,
            http_proxy=proxies,
            partition_ownership_expiration_interval=30,
        )
        _ = consumer.get_eventhub_properties()
        consumer.close()
    except azure_exceptions.EventHubError as exc:
        logger.error(vars(exc))
        logger.error(EH_FAILED_TO_CREATE_MSG.format(traceback.format_exc()))
        raise_user_readable_rest_error(exc)
    except Exception as e:
        logger.error(str(e))
        logger.error(EH_FAILED_TO_CREATE_MSG.format(traceback.format_exc()))
        raise RestError(400, str(e))


def create_event_hub_consumer_client(
    logger: logging.Logger,
    global_account: dict,
    input_item: dict,
    proxies: dict,
    session_key: str,
):
    """
    Creates eventhub consumer client
    :param logger: logger object
    :param global_account: azure app account for which credentials will be generated
    :param input_name: inputs with eventhub details
    :param proxies: proxy
    :param session_key: a session key
    :raises Exception: exception
    :returns consumer: instance of EventHub Consumer
    """
    credential = get_azure_event_hub_credentials(logger, global_account, proxies)

    if not credential:
        raise TaExecutionException("Not able to retrieve Azure Eventhub credentials", 1)

    # to get the partition id details
    consumer = EventHubConsumerClient(
        fully_qualified_namespace=input_item["event_hub_namespace"],
        eventhub_name=input_item["event_hub_name"],
        consumer_group=input_item["consumer_group"],
        credential=credential,
        http_proxy=proxies,
        partition_ownership_expiration_interval=30,
    )
    partition_ids = consumer.get_partition_ids()
    consumer.close()

    checkpoint_store = KVCheckpointStore(logger, input_item, session_key, partition_ids)

    consumer = EventHubConsumerClient(
        fully_qualified_namespace=input_item["event_hub_namespace"],
        eventhub_name=input_item["event_hub_name"],
        consumer_group=input_item["consumer_group"],
        credential=credential,
        http_proxy=proxies,
        checkpoint_store=checkpoint_store,
        partition_ownership_expiration_interval=300,
    )
    logger.debug("Consumer created successfully!")
    return consumer


class KVCheckpointStore(CheckpointStore):
    """
    This class is an implementation of `azure.eventhub.CheckpointStore`.

    It uses KVStoreCheckpoint to store the partition ownership and checkpoint data.
    """

    def __init__(
        self,
        logger: logging.Logger,
        input_item: dict,
        session_key: str,
        partition_ids: list,
    ):
        self.fully_qualified_namespace = input_item["event_hub_namespace"]
        self.eventhub_name = input_item["event_hub_name"]
        self.consumer_group = input_item["consumer_group"]
        self.checkpoint_key = f"event_hub_lastUpdate_{input_item['name']}"
        self.checkpoint = checkpointer.KVStoreCheckpointer(
            CHECKPOINTER, session_key, APP_NAME
        )

        if not self.checkpoint.get(self.checkpoint_key):
            self.initialize_kv_store_checkpoint(logger, partition_ids)
        # in case of dynamic partition addition in eventhub, ckpt would not have all new partition ids
        # so we will delete checkpoint and recreate checkpoint with updated partition ids
        elif len(self.checkpoint.get(self.checkpoint_key)) != len(partition_ids):
            delete_checkpoint(
                session_key, input_item["name"], EVENT_HUB_INPUT_TYPE, LOG_FILE_NAME
            )
            self.initialize_kv_store_checkpoint(logger, partition_ids)

    def initialize_kv_store_checkpoint(
        self, logger: logging.Logger, partition_ids: list
    ) -> None:
        ckpt_init = []
        for partition_id in partition_ids:
            ckpt_init.append(
                {
                    "partition_id": partition_id,
                    "owner_id": "",
                    "etag": str(uuid.uuid4()),
                    "last_modified_time": int(time.time()),
                    "offset": "",
                    "sequence_number": 0,
                }
            )
        logger.debug(f"Initializing checkpoint with ckpt_key={self.checkpoint_key}")
        self.checkpoint.update(self.checkpoint_key, ckpt_init)

    def list_ownership(self, fully_qualified_namespace, eventhub_name, consumer_group):
        result = []
        ownership_list = self.checkpoint.get(self.checkpoint_key)
        for ownership in ownership_list:
            result.append(
                {
                    "fully_qualified_namespace": fully_qualified_namespace,
                    "eventhub_name": eventhub_name,
                    "consumer_group": consumer_group,
                    "partition_id": str(ownership["partition_id"]),
                    "owner_id": ownership["owner_id"],
                    "etag": ownership["etag"],
                    "last_modified_time": ownership["last_modified_time"],
                }
            )
        return result

    def claim_ownership(self, ownership_list):
        records = self.checkpoint.get(self.checkpoint_key)
        etag_arr = ["" for _ in range(len(records))]
        for record in records:
            etag_arr[int(record["partition_id"])] = record["etag"]

        ownership_acquired = []
        for ownership in ownership_list:
            partition_id = int(ownership["partition_id"])
            owner_id = ownership["owner_id"]
            etag = ownership.get("etag")

            if etag != etag_arr[partition_id]:
                continue

            records = self.checkpoint.get(self.checkpoint_key)
            for record in records:
                if record["partition_id"] == str(partition_id):
                    record["owner_id"] = owner_id
                    record["etag"] = str(uuid.uuid4())
                    record["last_modified_time"] = int(time.time())

                    ownership["etag"] = record["etag"]
                    ownership["last_modified_time"] = record["last_modified_time"]
                    break
            self.checkpoint.update(self.checkpoint_key, records)
            ownership_acquired.append(ownership)
        return ownership_acquired

    def list_checkpoints(
        self, fully_qualified_namespace, eventhub_name, consumer_group
    ):
        result = []
        checkpoint_list = self.checkpoint.get(self.checkpoint_key)
        for partition_ckpt in checkpoint_list:
            result.append(
                {
                    "fully_qualified_namespace": fully_qualified_namespace,
                    "eventhub_name": eventhub_name,
                    "consumer_group": consumer_group,
                    "partition_id": partition_ckpt["partition_id"],
                    "offset": partition_ckpt["offset"],
                    "sequence_number": partition_ckpt["sequence_number"],
                }
            )
        return result

    def update_checkpoint(self, checkpoint):
        records = self.checkpoint.get(self.checkpoint_key)
        for record in records:
            if record["partition_id"] == checkpoint["partition_id"]:
                record["offset"] = checkpoint["offset"]
                record["sequence_number"] = int(checkpoint["sequence_number"])
                break
        self.checkpoint.update(self.checkpoint_key, records)


class EventHubConsumerHandler(object):
    """
    This class bridges events from an `EventHubConsumerClient` to a Splunk event writer.
    """

    def __init__(self, event_hub_consumer, event_writer, input_item, logger):
        self._event_hub_consumer = event_hub_consumer
        self._event_writer = event_writer
        self._thread = Thread(target=self._work_proc)
        self._partition_details = {}
        self._index = input_item.get("index")
        self._event_hub_name = input_item.get("event_hub_name")
        self._logger = logger
        self._streaming_event_types = input_item.get("streaming_event_types").split(",")
        self._skipped_events_count = 0
        self._ingested_events_count = 0

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._event_hub_consumer.close()
        self._event_hub_consumer = None
        self._thread.join()
        self._logger.error(
            f"Closing the consumer due to exception={exc_type} reason={exc_val}"
        )
        self._logger.error(f"Closing the consumer due to reason={exc_tb}")

    def is_alive(self):
        return self._thread.is_alive()

    @staticmethod
    def _normalize_event(event, logger) -> list:
        try:
            body = event.body
            if isinstance(body, bytes):
                return [body]
            return [line for line in body]
        except ValueError:
            logger.warn("The event content is empty.")
        return []

    def _decode_event(self, event):
        for line in self._normalize_event(event, self._logger):
            try:
                yield line.decode("utf-8")
            except UnicodeDecodeError:
                self._logger.warn("An error occurred during decoding the event.")
                yield line.hex()

    def _write_event(self, data: dict) -> None:
        event_type = data.get("category", "").replace("AdvancedHunting-", "")
        if not event_type or event_type not in self._streaming_event_types:
            self._skipped_events_count += 1
            if event_type:
                self._logger.debug(
                    f"Skipping writing event with event_type={event_type}"
                )
            return

        splunk_event = smi.Event(
            data=json.dumps(data),
            index=self._index,
            source=f"microsoft_defender_event_hub:{self._event_hub_name}",
            sourcetype="ms:defender:eventhub",
        )
        self._event_writer.write_event(splunk_event)
        self._ingested_events_count += 1

    def _select_elements(self, event):
        decoded_events = "".join([line for line in self._decode_event(event)])
        try:
            event_body = json.loads(decoded_events)
            if isinstance(event_body, dict) and isinstance(
                event_body.get("records"), (list, set, tuple)
            ):
                for data in event_body["records"]:
                    if isinstance(data, str):
                        self._write_event(json.loads(data))
                    else:
                        self._write_event(data)

        except ValueError:
            self._logger.debug("Splunk Event message body is not JSON.")

    def _get_partition_details(self, partition_id) -> dict:
        # if partition_details is not existing, then initialize and return it
        # otherwise return existing partition_details

        if partition_id in self._partition_details:
            partition_detail = self._partition_details[partition_id]
        else:
            partition_detail = {
                "is_done": -1,
                "total_received_batch_count": 0,
            }
            self._partition_details[partition_id] = partition_detail
        return partition_detail

    def _on_event_batch(self, context, event_batch):
        partition_id = context.partition_id
        partition_detail = self._get_partition_details(partition_id)

        if event_batch:
            self._logger.debug(
                f"Received Event batch. partition_id={context.partition_id} "
                f"event_batch_size={len(event_batch)}"
            )
            for event in event_batch:
                self._logger.debug(
                    f"Received event. partition_id={context.partition_id} "
                    f"offset={event.offset} sequence_number={event.sequence_number}"
                )
                self._select_elements(event)

            partition_detail["is_done"] = 0
            partition_detail["total_received_batch_count"] += len(event_batch)
            context.update_checkpoint()
        else:
            partition_detail["is_done"] += 1
            should_close = all(
                partition["is_done"] > 0
                for partition in self._partition_details.values()
            )
            if should_close:
                self._log_event_stats()

    def _log_event_stats(self):
        total_received_batch_count = 0

        for partition, details in self._partition_details.items():
            curr_partition_batch_count = details["total_received_batch_count"]
            total_received_batch_count += curr_partition_batch_count
            self._logger.debug(
                CURR_EVENT_BATCH_STATS.format(partition, curr_partition_batch_count)
            )
        self._logger.info(
            TOTAL_EVENT_BATCH_STATS.format(
                total_received_batch_count,
                self._skipped_events_count,
                self._ingested_events_count,
                int(time.time()),
            )
        )
        self._partition_details = {}
        self._skipped_events_count = 0
        self._ingested_events_count = 0

    def _on_error(self, context, error):
        event = context._last_received_event
        self._logger.error(f"partition_id={context.partition_id} error={error}")
        self._logger.info(
            f"Before encountering error, last_received_event had offset={event.offset} "
            f"sequence_number={event.sequence_number} enqueued_time={event.enqueued_time}"
        )

    def _work_proc(self):
        self._logger.info(f"Start collecting events. start_time={int(time.time())}")
        while self._event_hub_consumer:
            self._event_hub_consumer.receive_batch(
                on_event_batch=self._on_event_batch,
                max_wait_time=10,
                max_batch_size=300,
                on_error=self._on_error,
                starting_position="-1",
            )
