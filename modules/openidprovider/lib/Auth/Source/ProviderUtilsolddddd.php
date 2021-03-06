<?php

// namespace SimpleSAML\Module\openidprovider;

namespace SimpleSAML\Module\openidprovider\Auth\Source;
/**
 * Helper class for OpenID.
 *
 * @author Jaime Perez, UNINETT AS <jaime.perez@uninett.no>
 */
class ProviderUtils
{
    /**
     * List of log levels.
     *
     * This list is used to restore the log levels after some log levels are disabled.
     *
     * @var array
     */
    private static $logLevelStack = [];

    /**
     * The current mask of disabled log levels.
     *
     * Note: This mask is not directly related to the PHP error reporting level.
     *
     * @var int
     */
    public static $logMask = 0;


    /**
     * Disable reporting of the given log levels.
     *
     * Every call to this function must be followed by a call to popErrorMask();
     *
     * @param int $mask The log levels that should be masked.
     *
     * @throws \InvalidArgumentException If $mask is not an integer.
     * @return void
     *
     * @author Olav Morken, UNINETT AS <olav.morken@uninett.no>
     */
    public static function maskErrors(int $mask): void
    {
        $currentEnabled = error_reporting();
        self::$logLevelStack[] = [$currentEnabled, self::$logMask];

        $currentEnabled &= ~$mask;
        error_reporting($currentEnabled);
        self::$logMask |= $mask;
    }


    /**
     * Pop an error mask.
     *
     * This function restores the previous error mask.
     *
     * @return void
     * @author Olav Morken, UNINETT AS <olav.morken@uninett.no>
     */
    public static function popErrorMask(): void
    {
        $lastMask = array_pop(self::$logLevelStack);
        error_reporting($lastMask[0]);
        self::$logMask = $lastMask[1];
    }
}
